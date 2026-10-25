// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package policy

import (
	"regexp"
	"strings"
	"sync"
)

var globs sync.Map // pattern -> *regexp.Regexp (nil: never matches)

// fnmatchcase is Python's fnmatch.fnmatchcase: * any run of characters
// ("/" included), ? one character, [seq] / [!seq] a set; case-sensitive.
func fnmatchcase(name, pattern string) bool {
	if re, ok := globs.Load(pattern); ok {
		return re.(*regexp.Regexp) != nil && re.(*regexp.Regexp).MatchString(name)
	}
	re, err := regexp.Compile(translate(pattern))
	if err != nil {
		re = nil
	}
	globs.Store(pattern, re)
	return re != nil && re.MatchString(name)
}

// matches is policy_doc.matches: case-insensitive glob, any of the patterns.
func matches(value string, patterns []string) bool {
	v := strings.ToLower(value)
	for _, p := range patterns {
		if fnmatchcase(v, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func translate(pat string) string {
	rs := []rune(pat)
	var b strings.Builder
	b.WriteString(`(?s)\A`)
	star := false
	for i := 0; i < len(rs); {
		c := rs[i]
		i++
		if c != '*' {
			star = false
		}
		switch c {
		case '*':
			if !star {
				b.WriteString(`.*`)
			}
			star = true
		case '?':
			b.WriteString(`.`)
		case '[':
			j := i
			if j < len(rs) && rs[j] == '!' {
				j++
			}
			if j < len(rs) && rs[j] == ']' {
				j++
			}
			for j < len(rs) && rs[j] != ']' {
				j++
			}
			if j >= len(rs) {
				b.WriteString(`\[`)
				continue
			}
			stuff := rs[i:j]
			i = j + 1
			if len(stuff) == 0 {
				b.WriteString(`[^\x00-\x{10FFFF}]`) // empty set: never matches
				continue
			}
			if len(stuff) == 1 && stuff[0] == '!' {
				b.WriteString(`.`)
				continue
			}
			b.WriteByte('[')
			if stuff[0] == '!' {
				b.WriteByte('^')
				stuff = stuff[1:]
			}
			for _, r := range stuff {
				switch r {
				case '\\', '[', ']', '^':
					b.WriteByte('\\')
					b.WriteRune(r)
				default:
					b.WriteRune(r)
				}
			}
			b.WriteByte(']')
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`\z`)
	return b.String()
}
