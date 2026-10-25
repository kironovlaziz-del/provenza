// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package policy

// JSON values (as canon.Parse returns them: map[string]any, []any,
// json.Number, string, bool, nil) compared, converted and printed the way the
// server's Python does - so a rule decides the same here and a reason reads
// the same, word for word (sdk/testdata/policy-vectors.json).

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// number: a JSON number or a bool (Python's bool is an int) as an exact
// rational; inf / nan as a float. ok=false: not a number.
type number struct {
	rat   *big.Rat
	float float64 // set when rat is nil: inf or nan
}

func asNumber(v any, boolsCount bool) (number, bool) {
	switch x := v.(type) {
	case bool:
		if !boolsCount {
			return number{}, false
		}
		if x {
			return number{rat: big.NewRat(1, 1)}, true
		}
		return number{rat: new(big.Rat)}, true
	case json.Number:
		return parseNumber(string(x))
	case float64:
		return fromFloat(x), true
	case int:
		return number{rat: new(big.Rat).SetInt64(int64(x))}, true
	}
	return number{}, false
}

func parseNumber(s string) (number, bool) {
	if !strings.ContainsAny(s, ".eE") {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return number{}, false
		}
		return number{rat: new(big.Rat).SetInt(n)}, true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return number{}, false
	}
	return fromFloat(f), true
}

func fromFloat(f float64) number {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return number{float: f}
	}
	// the exact value of the binary float, as Python compares it with an int
	return number{rat: new(big.Rat).SetFloat64(f)}
}

// cmp: -1, 0, 1; ok=false when either is nan (every comparison is false).
func (a number) cmp(b number) (int, bool) {
	if a.rat == nil || b.rat == nil {
		fa, fb := a.f(), b.f()
		if math.IsNaN(fa) || math.IsNaN(fb) {
			return 0, false
		}
		switch {
		case fa < fb:
			return -1, true
		case fa > fb:
			return 1, true
		}
		return 0, true
	}
	return a.rat.Cmp(b.rat), true
}

func (a number) f() float64 {
	if a.rat == nil {
		return a.float
	}
	f, _ := a.rat.Float64()
	return f
}

// pyEqual is Python's == on parsed JSON values.
func pyEqual(a, b any) bool {
	na, aNum := asNumber(a, true)
	nb, bNum := asNumber(b, true)
	if aNum || bNum {
		if !aNum || !bNum {
			return false
		}
		c, ok := na.cmp(nb)
		return ok && c == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEqual(x[i], y[i]) {
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
			if !ok || !pyEqual(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// truthy is Python's bool().
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case json.Number:
		n, ok := asNumber(x, false)
		if !ok {
			return true
		}
		if n.rat == nil {
			return true // inf, nan
		}
		return n.rat.Sign() != 0
	}
	return true
}

// pyStr is Python's str(): a string itself, anything else its repr.
func pyStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return pyRepr(v)
}

// pyRepr is Python's repr() of a parsed JSON value. Object keys come out
// sorted (a Go map has no order; Python keeps the document's order).
func pyRepr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			if n, ok := new(big.Int).SetString(s, 10); ok {
				return n.String()
			}
			return s
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return s
		}
		return floatRepr(f)
	case float64:
		return floatRepr(x)
	case int:
		return strconv.Itoa(x)
	case string:
		return strRepr(x)
	case []any:
		parts := make([]string, len(x))
		for i, item := range x {
			parts[i] = pyRepr(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = strRepr(k) + ": " + pyRepr(x[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

func floatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	j, _ := canon.Parse([]byte(strconv.FormatFloat(f, 'e', -1, 64)))
	s, _ := canon.Text(j)
	return s
}

// strRepr: single quotes unless the text has ' and no " ; escapes as Python.
func strRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == utf8.RuneError:
			b.WriteString(`�`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f || unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

var pyFloatSyntax = regexp.MustCompile(`^[+-]?((\d(_?\d)*)(\.(\d(_?\d)*)?)?|\.\d(_?\d)*)([eE][+-]?\d(_?\d)*)?$`)

// pyFloat is Python's float() of a string: surrounding whitespace, digit
// underscores, inf / infinity / nan; no hexadecimal.
func pyFloat(s string) (number, bool) {
	t := strings.TrimFunc(s, unicode.IsSpace)
	switch strings.ToLower(strings.TrimLeft(t, "+-")) {
	case "inf", "infinity":
		if strings.HasPrefix(t, "-") {
			return number{float: math.Inf(-1)}, true
		}
		return number{float: math.Inf(1)}, true
	case "nan":
		return number{float: math.NaN()}, true
	}
	if !pyFloatSyntax.MatchString(t) {
		return number{}, false
	}
	f, err := strconv.ParseFloat(strings.ReplaceAll(t, "_", ""), 64)
	if err != nil && !strings.Contains(err.Error(), "value out of range") {
		return number{}, false
	}
	return fromFloat(f), true
}

// runeLen is Python's len() of a str.
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// truncate: the first n code points.
func truncate(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}
