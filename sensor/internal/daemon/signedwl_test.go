// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kironovlaziz-del/provenza/sensor/internal/canon"
	"github.com/kironovlaziz-del/provenza/sensor/internal/cgroups"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/trust"
)

func allow(dest string, ports []int, protos ...string) config.Allow {
	return config.Allow{Dest: dest, Ports: ports, Protocols: protos}
}

func TestCoversTarget(t *testing.T) {
	for _, c := range []struct {
		signed, server string
		want           bool
	}{
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "10.1.0.0/16", true},
		{"10.1.0.0/16", "10.0.0.0/8", false},
		{"10.0.0.0/8", "11.0.0.1", false},
		{"0.0.0.0/0", "::1", false},
		{"::/0", "2001:db8::1", true},
		{"api.example.com", "API.example.com.", true},
		{"api.example.com", "evil.example.com", false},
		{"*.corp", "crm.corp", true},
		{"*.corp", "*.eu.corp", true},
		{"*.corp", "corp", false},
		{"*.corp", "crm.corp.evil", false},
		{"api.example.com", "*.example.com", false},
		{"10.0.0.0/8", "crm.corp", false},
		{"crm.corp", "10.0.0.1", false},
	} {
		if got := coversTarget(c.signed, c.server); got != c.want {
			t.Errorf("%s covers %s: %v", c.signed, c.server, got)
		}
	}
}

func TestTheServerCannotLoosenASignedWorkload(t *testing.T) {
	agent := int64(5)
	signed := map[uint32]config.Workload{
		1: {ID: 1, Name: "payer", AgentID: &agent, CgroupPatterns: []string{"system.slice/payer.service"},
			RunAsUsers: []string{"payer"}, Mode: "enforce", DNS: "listed",
			EgressAllow: []config.Allow{allow("10.0.0.0/24", []int{8443}, "tcp"), allow("*.corp", []int{0}, "tcp")}},
		2: {ID: 2, Name: "gone", CgroupPatterns: []string{"system.slice/old.service"}, Mode: "enforce", DNS: "off"},
	}
	other := int64(9)
	server := &config.Policy{Schema: 1, Version: "7", Workloads: []config.Workload{
		{ID: 1, Name: "payer", AgentID: &other, Mode: "observe", DNS: "any", Isolated: false,
			CgroupPatterns: []string{"system.slice/payer.service", "system.slice/extra.service"},
			RunAsUsers:     []string{"payer", "extra"},
			EgressAllow: []config.Allow{
				allow("10.0.0.5", []int{8443, 22}, "tcp", "udp"), // only tcp/8443 is signed
				allow("0.0.0.0/0", []int{0}, "tcp"),              // wider than anything signed
				allow("crm.corp", []int{443}, "tcp"),
				allow("evil.example", []int{443}, "tcp"),
			}},
		{ID: 3, Name: "new", CgroupPatterns: []string{"system.slice/*"}, Mode: "alert", DNS: "off",
			EgressAllow: []config.Allow{allow("0.0.0.0/0", []int{0}, "tcp")}},
	}}
	eff, notes := constrain(server, signed)
	if eff.Version != "7" || len(eff.Workloads) != 3 {
		t.Fatalf("%+v", eff)
	}
	w := eff.Workloads[0]
	if !w.Signed || w.Mode != "enforce" || w.DNS != "listed" || *w.AgentID != 5 {
		t.Fatalf("payer: %+v", w)
	}
	got := map[string]bool{}
	for _, a := range w.EgressAllow {
		got[fmt.Sprint(a.Dest, "/", a.Protocols, "/", a.Ports)] = true
	}
	if len(w.EgressAllow) != 2 || !got["10.0.0.5/[tcp]/[8443]"] || !got["crm.corp/[tcp]/[443]"] {
		t.Fatalf("payer egress: %+v", w.EgressAllow)
	}
	if strings.Join(w.ExtraPatterns, ",") != "system.slice/extra.service" || strings.Join(w.ExtraUsers, ",") != "extra" {
		t.Fatalf("extras %v %v", w.ExtraPatterns, w.ExtraUsers)
	}
	if n := eff.Workloads[1]; n.ID != 3 || n.Signed || len(n.EgressAllow) != 1 {
		t.Fatalf("an unsigned workload is applied as sent: %+v", n)
	}
	if g := eff.Workloads[2]; g.ID != 2 || !g.Signed || g.Mode != "enforce" {
		t.Fatalf("a signed workload the server dropped is governed as signed: %+v", g)
	}
	if len(notes) != 2 || !strings.Contains(notes[0], "workload 1: 5 allowed") || !strings.Contains(notes[1], "workload 2") {
		t.Fatalf("notes %q", notes)
	}

	// isolation by the server holds; a stricter server mode holds
	server.Workloads[0].Isolated, server.Workloads[0].Mode = true, "enforce"
	signed[1] = func() config.Workload { s := signed[1]; s.Mode = "alert"; return s }()
	eff, _ = constrain(server, signed)
	if !eff.Workloads[0].Isolated || eff.Workloads[0].Mode != "enforce" {
		t.Fatalf("%+v", eff.Workloads[0])
	}
}

func TestSignedPatternsComeFirst(t *testing.T) {
	pats := []pattern{
		{p: cgroups.NewPattern("system.slice/*", 3), wid: 3, prio: 1},
		{p: cgroups.NewPattern("system.slice/payer.service", 1), wid: 1, prio: 0},
	}
	if wid, ok := matchPattern(sortPatterns(pats), "system.slice/payer.service"); !ok || wid != 1 {
		t.Fatalf("the server's pattern took a signed workload's cgroup: %d", wid)
	}
	users := userAssignments([]config.Workload{
		{ID: 3, RunAsUsers: []string{"payer"}},
		{ID: 1, Signed: true, RunAsUsers: []string{"payer"}, ExtraUsers: []string{"extra"}},
	})
	if users[0].name != "payer" || users[0].wid != 1 || !users[0].signed {
		t.Fatalf("%+v", users)
	}
}

func TestSignedWorkloadsFromARelease(t *testing.T) {
	raw := []byte(`{"egress_workloads": {"4": {"name": "w", "agent_id": 7, "cgroup_patterns": ["a/b"], "run_as_users": [],
		"egress_allow": [{"dest": "10.0.0.0/8", "ports": [443], "protocols": ["tcp"]}], "ingress_allow": [],
		"dns": "off", "mode": "enforce", "isolated": false, "enabled": true},
		"5": {"name": "off", "enabled": false, "mode": "enforce", "dns": "off"}}}`)
	v, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ws, ok, err := signedWorkloads(&trust.Release{Bundle: v.(map[string]any)})
	if err != nil || !ok || len(ws) != 1 || ws[4].ID != 4 || *ws[4].AgentID != 7 || ws[4].EgressAllow[0].Ports[0] != 443 {
		t.Fatalf("%+v %v %v", ws, ok, err)
	}
	if _, ok, _ := signedWorkloads(&trust.Release{Bundle: map[string]any{}}); ok {
		t.Fatal("an old release has signed workloads")
	}
	bad, _ := canon.Parse([]byte(`{"egress_workloads": {"4294967040": {"enabled": true}}}`))
	if _, _, err := signedWorkloads(&trust.Release{Bundle: bad.(map[string]any)}); err == nil {
		t.Fatal("a reserved id was taken")
	}
}
