// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// The input schema of an HTTP tool, checked deeply: the server's
// backend/app/pvp/schema_check.py, rule for rule, tested against the same
// vectors (sdk/testdata/schema-vectors.json).
//
//   - a small, strict subset of JSON Schema: type, enum, const, properties,
//     required, additionalProperties, items, minItems, maxItems, minLength,
//     maxLength, pattern, minimum, maximum, exclusiveMinimum,
//     exclusiveMaximum, and annotations nobody reads; any other keyword makes
//     the call refused
//   - pattern: regexp (RE2), as google-re2 on the server: linear time, \d is
//     0-9, $ is the end of the text; it searches, it is not anchored
//   - numbers: integers compared exactly; an integer against any other number
//     as Python compares them (big.Float of both)
//   - strings: lengths in code points
//   - nesting: the schema 16, the arguments 32

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"unicode/utf8"
)

const (
	maxSchemaDepth = 16
	maxValueDepth  = 32
	maxPattern     = 512
	maxCount       = 1_000_000
	maxProblems    = 20
)

var (
	schemaKeywords = map[string]bool{"type": true, "enum": true, "const": true, "properties": true, "required": true,
		"additionalProperties": true, "items": true, "minItems": true, "maxItems": true, "minLength": true,
		"maxLength": true, "pattern": true, "minimum": true, "maximum": true, "exclusiveMinimum": true,
		"exclusiveMaximum": true}
	schemaAnnotations = map[string]bool{"title": true, "description": true, "default": true, "examples": true,
		"format": true, "$schema": true, "$comment": true, "deprecated": true, "readOnly": true, "writeOnly": true}
	schemaTypes = map[string]bool{"string": true, "integer": true, "number": true, "boolean": true, "object": true,
		"array": true, "null": true}
)

var patterns sync.Map // pattern -> *regexp.Regexp (or error)

func compiledPattern(p string) (*regexp.Regexp, error) {
	if v, ok := patterns.Load(p); ok {
		if rx, ok := v.(*regexp.Regexp); ok {
			return rx, nil
		}
		return nil, v.(error)
	}
	rx, err := regexp.Compile(p)
	if err != nil {
		patterns.Store(p, err)
		return nil, err
	}
	patterns.Store(p, rx)
	return rx, nil
}

// isNumber: a JSON number that is a finite float64 (Python reads 1e400 as inf: not a number there either).
func isNumber(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	return err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
}

func isCount(v any) bool {
	if !isInteger(v) {
		return false
	}
	i, ok := new(big.Int).SetString(string(v.(json.Number)), 10)
	return ok && i.Sign() >= 0 && i.Cmp(big.NewInt(maxCount)) <= 0
}

func countOf(v any) int {
	i, _ := strconv.Atoi(string(v.(json.Number)))
	return i
}

// bigOf: the number, exactly: an integer as itself, any other as the float64 Python reads.
func bigOf(n json.Number) *big.Float {
	if isInteger(n) {
		i, _ := new(big.Int).SetString(string(n), 10)
		return new(big.Float).SetPrec(uint(max(64, i.BitLen()+1))).SetInt(i)
	}
	f, _ := strconv.ParseFloat(string(n), 64)
	return new(big.Float).SetPrec(64).SetFloat64(f)
}

func numCmp(a, b json.Number) int { return bigOf(a).Cmp(bigOf(b)) }

// jsonEqual: equality of JSON values; true is not 1, 1 is 1.0.
func jsonEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && isNumber(x) && isNumber(y) && numCmp(x, y) == 0
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !jsonEqual(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

func valueTypeOK(v any, name string) bool {
	switch name {
	case "string":
		_, ok := v.(string)
		return ok
	case "integer":
		return isInteger(v)
	case "number":
		return isNumber(v)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "null":
		return v == nil
	}
	return false
}

func label(at string) string {
	if at == "" {
		return "the arguments"
	}
	return "argument '" + at + "'"
}

// valueDepthOK: the arguments are not nested deeper than maxValueDepth (checked even without a schema).
func valueDepthOK(v any, depth int) bool {
	if depth > maxValueDepth {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		for _, y := range x {
			if !valueDepthOK(y, depth+1) {
				return false
			}
		}
	case []any:
		for _, y := range x {
			if !valueDepthOK(y, depth+1) {
				return false
			}
		}
	}
	return true
}

// valueProblems: why v does not match the schema (none: it does). A schema this
// check does not understand is a problem too: the call is refused, not waved through.
func valueProblems(schema, v any) []string {
	var problems []string
	checkValue(schema, v, "", 0, &problems)
	if len(problems) > maxProblems {
		problems = problems[:maxProblems]
	}
	return problems
}

func checkValue(schema, v any, at string, depth int, problems *[]string) {
	add := func(format string, a ...any) { *problems = append(*problems, fmt.Sprintf(format, a...)) }
	if len(*problems) >= maxProblems {
		return
	}
	if depth > maxValueDepth || depth > maxSchemaDepth {
		add("%s is nested too deeply", label(at))
		return
	}
	s, ok := schema.(map[string]any)
	if !ok {
		add("the schema of %s is not an object", label(at))
		return
	}
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !schemaKeywords[k] && !schemaAnnotations[k] {
			add("the schema of %s uses '%s', which is not supported", label(at), k)
			return
		}
	}
	if t, ok := s["type"]; ok {
		names, isList := t.([]any)
		if !isList {
			names = []any{t}
		}
		match := false
		for _, n := range names {
			name, isStr := n.(string)
			if !isStr || !schemaTypes[name] {
				add("the schema of %s has an unknown type", label(at))
				return
			}
			if valueTypeOK(v, name) {
				match = true
			}
		}
		if !match {
			add("%s is not of type %v", label(at), t)
			return
		}
	}
	if e, ok := s["enum"]; ok {
		list, isList := e.([]any)
		found := false
		for _, x := range list {
			if jsonEqual(v, x) {
				found = true
				break
			}
		}
		if !isList || !found {
			add("%s is not one of the allowed values", label(at))
		}
	}
	if c, ok := s["const"]; ok && !jsonEqual(v, c) {
		add("%s is not the allowed value", label(at))
	}

	switch x := v.(type) {
	case string:
		n := utf8.RuneCountInString(x)
		if m := s["minLength"]; isCount(m) && n < countOf(m) {
			add("%s is shorter than %d characters", label(at), countOf(m))
		}
		if m := s["maxLength"]; isCount(m) && n > countOf(m) {
			add("%s is longer than %d characters", label(at), countOf(m))
		}
		if p, ok := s["pattern"]; ok {
			ps, isStr := p.(string)
			matched := false
			if isStr && utf8.RuneCountInString(ps) <= maxPattern {
				if rx, err := compiledPattern(ps); err == nil {
					matched = rx.MatchString(x)
				}
			}
			if !matched {
				add("%s does not match the pattern", label(at))
			}
		}
	case json.Number:
		if !isNumber(x) {
			break
		}
		for _, key := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"} {
			b, ok := s[key]
			if !ok {
				continue
			}
			if !isNumber(b) {
				add("the schema of %s: %s is not a number", label(at), key)
				continue
			}
			c := numCmp(x, b.(json.Number))
			if key == "minimum" && c < 0 || key == "maximum" && c > 0 ||
				key == "exclusiveMinimum" && c <= 0 || key == "exclusiveMaximum" && c >= 0 {
				add("%s is out of range (%s %s)", label(at), key, b)
			}
		}
	case []any:
		if m := s["minItems"]; isCount(m) && len(x) < countOf(m) {
			add("%s has fewer than %d items", label(at), countOf(m))
		}
		if m := s["maxItems"]; isCount(m) && len(x) > countOf(m) {
			add("%s has more than %d items", label(at), countOf(m))
		}
		if items, ok := s["items"]; ok {
			for i, item := range x {
				checkValue(items, item, fmt.Sprintf("%s[%d]", at, i), depth+1, problems)
			}
		}
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		prefix := ""
		if at != "" {
			prefix = at + "."
		}
		if req, ok := s["required"].([]any); ok {
			for _, n := range req {
				if name, ok := n.(string); ok {
					if _, present := x[name]; !present {
						add("missing argument '%s%s'", prefix, name)
					}
				}
			}
		}
		extra, hasExtra := s["additionalProperties"]
		names := make([]string, 0, len(x))
		for k := range x {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			sub := prefix + name
			if p, ok := props[name]; ok {
				checkValue(p, x[name], sub, depth+1, problems)
			} else if hasExtra && extra == false {
				add("unexpected argument '%s'", sub)
			} else if em, ok := extra.(map[string]any); ok {
				checkValue(em, x[name], sub, depth+1, problems)
			}
		}
	}
}

// formProblems: a form body carries strings only, so the API reads back
// exactly the arguments the permit is bound to.
func formProblems(args map[string]any) []string {
	var keys []string
	for k, v := range args {
		if _, ok := v.(string); !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("argument '%s' must be a string (the tool sends a form)", k))
	}
	return out
}
