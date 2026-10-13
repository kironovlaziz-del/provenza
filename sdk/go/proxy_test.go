// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The proxy computes the same descriptor (sdk/testdata/proxy-descriptor-vectors.json).
func TestProxyDescriptorVectors(t *testing.T) {
	raw, err := os.ReadFile("../testdata/proxy-descriptor-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Route, Method, Path, Query, Body string
			Descriptor                       map[string]any
		}
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.Vectors) == 0 {
		t.Fatal("no vectors", err)
	}
	for _, v := range file.Vectors {
		got, err := ProxyDescriptor(v.Route, v.Method, v.Path, v.Query, []byte(v.Body))
		if err != nil {
			t.Fatal(err)
		}
		if a, b := jsonOf(t, got), jsonOf(t, v.Descriptor); a != b {
			t.Errorf("%s %s:\n got  %s\n want %s", v.Method, v.Path, a, b)
		}
	}
	for _, bad := range []string{"v1/charges", "/v1/charges?limit=3"} {
		if _, err := ProxyDescriptor("stripe", "GET", bad, "", nil); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestProxyCheck(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	body := []byte(`{"amount":1000}`)
	chk, err := a.ProxyCheck(context.Background(), "stripe", "post", "/v1/charges", "", body)
	if err != nil || !chk.Allowed() {
		t.Fatal(chk, err)
	}
	sent := f.checks[chk.CheckID]
	want, _ := ProxyDescriptor("stripe", "POST", "/v1/charges", "", body)
	if sent["action_type"] != "proxy" || sent["tool_name"] != "proxy.stripe" ||
		jsonOf(t, sent["input"]) != jsonOf(t, want) {
		t.Fatalf("sent %v", sent)
	}
	if h := chk.ProxyHeaders(); len(h) != 1 || h["X-Provenza-Check-Id"] != chk.CheckID {
		t.Fatalf("headers %v", h)
	}
}

func TestPermitHeaders(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	chk, err := a.Check(context.Background(), "db.read", map[string]any{"q": 1})
	if err != nil || !chk.Allowed() || chk.Permit != "permit-of-"+chk.CheckID {
		t.Fatal(chk, err)
	}
	if h := chk.PermitHeaders(); len(h) != 1 || h["Provenza-Permit"] != chk.Permit {
		t.Fatalf("headers %v", h)
	}
	if h := (&Check{Decision: "denied"}).PermitHeaders(); len(h) != 0 {
		t.Fatalf("a refused check has no permit: %v", h)
	}
}

func TestInvokeHTTPTool(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	out, err := a.Invoke(context.Background(), "crm.set_tier", map[string]any{"id": "42", "tier": "gold"})
	if err != nil || out["decision"] != "allowed" || jsonOf(t, out["body"]) != `{"echo":{"id":"42","tier":"gold"}}` {
		t.Fatal(out, err)
	}
	f.verdicts["crm.delete"] = "pending_approval"
	_, err = a.Invoke(context.Background(), "crm.delete", map[string]any{"id": "42"})
	var denied *DeniedError
	if !errors.As(err, &denied) || !denied.ApprovalRequired() || denied.ActionID == nil || *denied.ActionID != 10 {
		t.Fatalf("want approval required, got %v", err)
	}
}

func TestEgressSelfcheck(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	f.beaconURL = "http://127.0.0.1:9/egress-beacon/tok" // nothing there
	out, err := a.EgressSelfcheck(context.Background(), time.Second)
	if err != nil || out["verdict"] != "confined" {
		t.Fatal(out, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f.egressTargets = []any{ln.Addr().String(), "127.0.0.1:9"}
	if out, err := a.EgressSelfcheck(context.Background(), time.Second); err != nil || out["verdict"] != "open" {
		t.Fatal(out, err)
	}
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer beacon.Close()
	f.egressTargets, f.beaconURL = nil, beacon.URL+"/egress-beacon/tok"
	if out, err := a.EgressSelfcheck(context.Background(), time.Second); err != nil || out["verdict"] != "open" {
		t.Fatal(out, err)
	}
}

func TestAttest(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	out, err := a.Attest(context.Background(), "  eyJ.workload.token\n")
	if err != nil || out["ok"] != true || out["evidence"] != "eyJ.workload.token" {
		t.Fatal(out, err)
	}
}
