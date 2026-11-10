// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// The server's schema_check.py and this proxy give the same answers
// (sdk/testdata/schema-vectors.json, checked there by tests/test_schema_vectors.py).
func schemaVectors(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "testdata", "schema-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc.(map[string]any)
}

func vectorValue(v any) any {
	if s, ok := v.(string); ok && strings.HasPrefix(s, "DEEP") {
		n, _ := strconv.Atoi(s[4:])
		var out any = "leaf"
		for i := 0; i < n; i++ {
			out = map[string]any{"x": out}
		}
		return out
	}
	return v
}

func TestSchemaVectors(t *testing.T) {
	doc := schemaVectors(t)
	groups, _ := doc["groups"].([]any)
	if len(groups) == 0 {
		t.Fatal("no groups")
	}
	n := 0
	for _, g := range groups {
		group := g.(map[string]any)
		for _, c := range group["cases"].([]any) {
			cs := c.(map[string]any)
			args, ok := vectorValue(cs["value"]).(map[string]any)
			if !ok {
				t.Fatalf("%s: a case that is not an object", group["name"])
			}
			problems := argumentProblems(group["schema"], args, "https://api.example/x", "")
			if valid := cs["valid"] == true; valid != (len(problems) == 0) {
				t.Errorf("%s: %v: valid %v, problems %v", group["name"], cs["value"], valid, problems)
			}
			n++
		}
	}
	if n < 50 {
		t.Fatalf("only %d cases", n)
	}
}

func TestFormVectors(t *testing.T) {
	for _, c := range schemaVectors(t)["form"].([]any) {
		cs := c.(map[string]any)
		args := cs["arguments"].(map[string]any)
		problems := argumentProblems(nil, args, "https://api.example/x", formEncoding)
		if refused := cs["refused"] == true; refused != (len(problems) > 0) {
			t.Fatalf("%v: refused %v, problems %v", args, refused, problems)
		}
		if len(problems) > 0 {
			continue
		}
		_, body, err := buildRequest("POST", "https://api.example/x", args, formEncoding)
		if err != nil || string(body) != cs["body"] {
			t.Fatalf("%v: body %q, want %q (%v)", args, body, cs["body"], err)
		}
	}
}

func TestSchemaPatternRunsInLinearTime(t *testing.T) {
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"s": map[string]any{"type": "string", "pattern": "^(a+)+$"}}}
	started := time.Now()
	if len(argumentProblems(schema, map[string]any{"s": strings.Repeat("a", 100_000) + "b"}, "https://x/", "")) == 0 {
		t.Fatal("matched")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("too slow")
	}
}
