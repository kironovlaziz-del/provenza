// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// The server's own outputs (sdk/testdata/canonical-vectors.json).
func TestCanonicalMatchesTheServer(t *testing.T) {
	raw, err := os.ReadFile("../testdata/canonical-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct{ JSON, Canonical, SHA256 string }
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		if v.JSON == `{"lone":"\ud800"}` {
			// a Go string cannot hold a lone surrogate: json.Marshal sends U+FFFD
			// instead, and the server hashes that - which is what Canonical computes
			continue
		}
		var value any
		if err := json.Unmarshal([]byte(v.JSON), &value); err != nil {
			t.Fatal(err)
		}
		got, err := Canonical(value)
		if err != nil {
			t.Fatalf("%s: %v", v.JSON, err)
		}
		if got != v.Canonical {
			t.Errorf("canonical differs\n json %s\n got  %s\n want %s", v.JSON, got, v.Canonical)
		}
		if h, _ := ContentHash(value); h != v.SHA256 {
			t.Errorf("hash differs for %s", v.JSON)
		}
	}
}

func TestPythonFloatRepr(t *testing.T) {
	cases := map[float64]string{1e-7: "1e-07", 1e-5: "1e-05", 1e-4: "0.0001", 1e16: "1e+16", 1e15: "1000000000000000.0",
		1.5: "1.5", 100.25: "100.25", 5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308",
		-2.5e-10: "-2.5e-10", math.Copysign(0, -1): "-0.0", 0: "0.0"}
	for f, want := range cases {
		if got := pyFloatRepr(f); got != want {
			t.Errorf("repr(%v) = %s, want %s", f, got, want)
		}
	}
}

func TestStructsAndNumbersAsTheServerParsesThem(t *testing.T) {
	type in struct {
		B int     `json:"b"`
		A float64 `json:"a"`
		Z string  `json:"z"`
	}
	// float64 1e21 is marshaled 1e+21 (a Python float); 2.0 is marshaled 2 (a Python int)
	got, err := Canonical(map[string]any{"s": in{B: 1, A: 2.0, Z: "<é>"}, "big": 1e21, "f": 0.1})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"big":1e+21,"f":0.1,"s":{"a":2,"b":1,"z":"<\u00e9>"}}`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
	if _, err := Canonical(math.NaN()); err == nil {
		t.Error("NaN must be refused")
	}
}
