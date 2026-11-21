// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package canon

import (
	"encoding/json"
	"os"
	"testing"
)

// Any JSON a client sends: the canonical text, when there is one, is pure
// ASCII and a fixed point (canonical text parsed again writes the same text).
// `go test -fuzz=FuzzText ./internal/canon` explores; plain `go test` runs the seeds.
func FuzzText(f *testing.F) {
	for _, s := range []string{`{}`, `[]`, `null`, `true`, `0`, `-0`, `1.0`, `1e-07`, `1E+16`, `0.0001`,
		`123456789012345678901234567890`, `"é😀"`, `{"b":1,"a":[1,2,{"c":"\n"}]}`, `"\u007f"`, `1e400`} {
		f.Add([]byte(s))
	}
	if raw, err := os.ReadFile("../../../sdk/testdata/canonical-vectors.json"); err == nil {
		var cases []struct {
			JSON string `json:"json"`
		}
		if json.Unmarshal(raw, &cases) == nil {
			for _, c := range cases {
				f.Add([]byte(c.JSON))
			}
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := Parse(raw)
		if err != nil {
			return
		}
		text, err := Text(v)
		if err != nil {
			return // a value with no canonical form (an infinite float) is refused, not written
		}
		for i := 0; i < len(text); i++ {
			if text[i] < 0x20 || text[i] > 0x7e {
				t.Fatalf("byte %#x at %d of %q is not printable ASCII", text[i], i, text)
			}
		}
		again, err := Parse([]byte(text))
		if err != nil {
			t.Fatalf("canonical text %q does not parse: %v", text, err)
		}
		text2, err := Text(again)
		if err != nil || text2 != text {
			t.Fatalf("not a fixed point:\n%q\n%q (%v)", text, text2, err)
		}
		if _, err := UnicodeText(v); err != nil {
			t.Fatalf("UnicodeText refused what Text wrote: %v", err)
		}
	})
}
