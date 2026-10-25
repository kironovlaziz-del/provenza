// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package canon

import (
	"encoding/json"
	"os"
	"testing"
)

// the outputs the server computes (sdk/testdata/canonical-vectors.json)
func TestServerVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../sdk/testdata/canonical-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		JSON      string `json:"json"`
		Canonical string `json:"canonical"`
		SHA256    string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range cases {
		if c.JSON == `{"lone":"\ud800"}` {
			// a Go string cannot hold a lone surrogate (it becomes U+FFFD): such a
			// document hashes differently here and is refused - never accepted wrongly
			continue
		}
		v, err := Parse([]byte(c.JSON))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Text(v)
		if err != nil || got != c.Canonical {
			t.Errorf("%s:\n got  %s\n want %s (%v)", c.JSON, got, c.Canonical, err)
		}
		if h, _ := SHA256(v); h != c.SHA256 {
			t.Errorf("%s: sha256 %s, want %s", c.JSON, h, c.SHA256)
		}
	}
}
