// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package policy

// Argument rules (OWASP ASI02), the port of backend/app/services/argument_rules.py.
// Fail-closed as there: a missing argument, a list with one bad element, a
// subject over MAX_SUBJECT, a rule that cannot be evaluated - all violate.
// A regular expression the Go engine (RE2) cannot compile - a Python-only
// construct - violates too: here a rule can only be stricter, never looser.

import (
	"math/big"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

const maxSubject = 10_000

var regexes sync.Map // pattern -> *regexp.Regexp (nil: does not compile)

func compiled(pattern string) *regexp.Regexp {
	if re, ok := regexes.Load(pattern); ok {
		r, _ := re.(*regexp.Regexp)
		return r
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	regexes.Store(pattern, re)
	return re
}

type missingT struct{}

var missing = missingT{}

func getPath(data any, path string) any {
	cur := data
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return missing
		}
		v, ok := m[part]
		if !ok {
			return missing
		}
		cur = v
	}
	return cur
}

// getStr is str(rule.get(key, "")).
func getStr(rule map[string]any, key string) string {
	v, ok := rule[key]
	if !ok {
		return ""
	}
	return pyStr(v)
}

func ratOf(n int) *big.Rat { return new(big.Rat).SetInt64(int64(n)) }

// isPySpace: what Python's str.strip() removes.
func isPySpace(r rune) bool {
	return unicode.IsSpace(r) || r == 0x1c || r == 0x1d || r == 0x1e || r == 0x1f
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

// normpath is Python's posixpath.normpath.
func normpath(p string) string {
	if p == "" {
		return "."
	}
	initial := 0
	if strings.HasPrefix(p, "/") {
		initial = 1
		if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
			initial = 2
		}
	}
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." {
			continue
		}
		if c != ".." || (initial == 0 && len(out) == 0) || (len(out) > 0 && out[len(out)-1] == "..") {
			out = append(out, c)
		} else if len(out) > 0 {
			out = out[:len(out)-1]
		}
	}
	res := strings.Repeat("/", initial) + strings.Join(out, "/")
	if res == "" {
		return "."
	}
	return res
}

func normalise(text string) string {
	if !strings.Contains(text, "://") && (strings.Contains(text, "/") || strings.Contains(text, "..")) {
		n := normpath(text)
		if strings.HasSuffix(text, "/") && n != "/" {
			return n + "/"
		}
		return n
	}
	return text
}

// itemNumber is argument_rules._number: a number, or a string Python's float() reads.
func itemNumber(v any) (number, bool) {
	if _, isBool := v.(bool); isBool {
		return number{}, false
	}
	if n, ok := asNumber(v, false); ok {
		return n, true
	}
	if s, ok := v.(string); ok {
		return pyFloat(s)
	}
	return number{}, false
}

func holdsOne(op string, item, expected any) bool {
	switch op {
	case "equals":
		return pyEqual(item, expected)
	case "in", "not_in":
		found := false
		for _, e := range asList(expected) {
			if pyEqual(item, e) {
				found = true
				break
			}
		}
		return found == (op == "in")
	case "max", "min":
		n, ok := itemNumber(item)
		if !ok {
			return false
		}
		limit, ok := asNumber(expected, true)
		if !ok {
			return false // a broken stored rule fails closed
		}
		c, ok := n.cmp(limit)
		if !ok {
			return false
		}
		if op == "max" {
			return c <= 0
		}
		return c >= 0
	case "max_length":
		limit, ok := asNumber(expected, true)
		if !ok {
			return false
		}
		c, ok := number{rat: ratOf(runeLen(pyStr(item)))}.cmp(limit)
		return ok && c <= 0
	}
	s, ok := item.(string)
	if !ok {
		return false
	}
	switch op {
	case "starts_with":
		p := normalise(s)
		for _, e := range asList(expected) {
			pre, ok := e.(string)
			if !ok {
				return false
			}
			if strings.HasPrefix(p, pre) || p == strings.TrimRight(pre, "/") {
				return true
			}
		}
		return false
	case "domain_in":
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return false
		}
		domain := strings.TrimFunc(s[at+1:], isPySpace)
		domain = strings.ToLower(strings.TrimRight(strings.TrimRight(domain, ">"), "."))
		for _, e := range asList(expected) {
			d, ok := e.(string)
			if !ok {
				return false
			}
			d = strings.TrimLeft(strings.TrimLeft(strings.ToLower(strings.TrimFunc(d, isPySpace)), "@"), ".")
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return true
			}
		}
		return false
	case "matches", "not_matches":
		if runeLen(s) > maxSubject {
			return false
		}
		pattern, ok := expected.(string)
		if !ok {
			return false
		}
		re := compiled(pattern)
		if re == nil {
			return false
		}
		found := re.MatchString(s)
		return found == (op == "matches")
	}
	return false
}

func holds(op string, actual, expected any) bool {
	for _, item := range asList(actual) {
		if !holdsOne(op, item, expected) {
			return false
		}
	}
	return true
}

func describe(rule map[string]any) string {
	value := pyRepr(rule["value"])
	if runeLen(value) > 80 {
		value = truncate(value, 77) + "..."
	}
	return "argument '" + pyStr(rule["arg"]) + "' must satisfy " + pyStr(rule["op"]) + " " + value
}

// evaluateArgumentRules returns "ok" | "deny" | "approval" and the reason.
func evaluateArgumentRules(rules any, tool string, input map[string]any) (string, string) {
	verdict, detail := "ok", ""
	list, _ := rules.([]any)
	for _, r := range list {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if !fnmatchcase(tool, getStr(rule, "tool")) {
			continue
		}
		actual := getPath(input, getStr(rule, "arg"))
		var held bool
		var why string
		if actual == missing {
			held, why = false, "argument '"+pyStr(rule["arg"])+"' is required by policy but missing"
		} else {
			op, _ := rule["op"].(string)
			held = holds(op, actual, rule["value"])
			why = describe(rule)
		}
		if held {
			continue
		}
		effect, has := rule["effect"]
		if !has {
			effect = "deny"
		}
		if effect == "require_approval" {
			if verdict == "ok" {
				verdict, detail = "approval", why
			}
		} else {
			return "deny", why
		}
	}
	return verdict, detail
}
