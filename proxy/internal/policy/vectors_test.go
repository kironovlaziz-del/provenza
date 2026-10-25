// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package policy

import (
	"os"
	"reflect"
	"testing"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

func str(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

// Every case of sdk/testdata/policy-vectors.json - the server's decisions
// (backend/app/pvp/bundle_eval.py) - decided the same here, word for word.
func TestServerVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../sdk/testdata/policy-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	d := doc.(map[string]any)
	base := d["base_bundle"].(map[string]any)
	manifest := d["manifest"].(map[string]any)
	release, _ := intOf(d["release"])
	cases := d["cases"].([]any)
	if len(cases) < 50 {
		t.Fatalf("only %d cases", len(cases))
	}
	ran := 0
	for _, c := range cases {
		c := c.(map[string]any)
		name := c["name"].(string)
		bundle := map[string]any{}
		for k, v := range base {
			bundle[k] = v
		}
		for k, v := range c["bundle"].(map[string]any) {
			bundle[k] = v
		}
		req := c["request"].(map[string]any)
		agent, _ := intOf(req["agent_id"])
		at, _ := req["action_type"].(string)
		tool, _ := req["tool_name"].(string)
		r := Request{AgentID: int64(agent), ActionType: at, ToolName: tool, Input: req["input"],
			ToolVersion: str(req["tool_version"]), ToolDigest: str(req["tool_digest"])}
		if fp, ok := req["key_fingerprint"]; ok {
			r.KeyChecked, r.KeyFingerprint = true, str(fp)
		}
		if at == "egress" {
			continue // judged by the server only (the AI domain catalog and its built-in hints)
		}
		now, _ := asNumber(c["now"], false)
		got := Evaluate(&Policy{Number: release, Bundle: bundle, Manifest: manifest}, r, now.f())
		want := c["expect"].(map[string]any)
		if got.Result != want["decision"] || got.Reason != want["reason"] {
			t.Errorf("%s:\n got  %s %q\n want %s %q", name, got.Result, got.Reason, want["decision"], want["reason"])
		}
		gotCaps := append([]string{}, got.RequiredCapabilities...)
		if wantCaps := stringsOf(want["required_capabilities"]); !reflect.DeepEqual(gotCaps, wantCaps) {
			t.Errorf("%s: required capabilities %v, want %v", name, got.RequiredCapabilities, wantCaps)
		}
		ran++
	}
	t.Logf("%d cases", ran)
}
