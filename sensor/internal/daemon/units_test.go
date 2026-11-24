// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/cgroups"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
)

func TestHostUnits(t *testing.T) {
	dir := t.TempDir()
	dockerID := strings.Repeat("a1", 32)
	podmanID := strings.Repeat("b2", 32)
	unnamed := strings.Repeat("c3", 32)
	_ = os.MkdirAll(filepath.Join(dir, "docker", dockerID), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "docker", dockerID, "config.v2.json"),
		[]byte(`{"ID":"`+dockerID+`","Name":"/support-bot","Config":{"Env":["SECRET=x"]}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "containers.json"),
		[]byte(`[{"id":"`+podmanID+`","names":["research-agent"],"layer":"x"}]`), 0o644)
	src := unitSources{dockerDir: filepath.Join(dir, "docker"), podmanJSON: filepath.Join(dir, "containers.json")}

	dirs := []cgroups.Dir{
		{Rel: "system.slice"},
		{Rel: "system.slice/ssh.service"},
		{Rel: "system.slice/billing-agent.service"},
		{Rel: "system.slice/billing-agent.service/libpod-payload-" + podmanID}, // inside a service: the service covers it
		{Rel: "system.slice/docker-" + dockerID + ".scope"},
		{Rel: "machine.slice/libpod-" + podmanID + ".scope"},
		{Rel: "machine.slice/libpod-" + unnamed + ".scope"},
		{Rel: "user.slice/user-1000.slice/session-3.scope"}, // a login session: not listed
		{Rel: "provenza-run/provenza-agent-7-abc"},          // a run cgroup: not listed
	}
	got := hostUnits(dirs, src)
	want := []client.HostUnit{
		{Kind: "service", Name: "billing-agent.service", Cgroup: "system.slice/billing-agent.service"},
		{Kind: "service", Name: "ssh.service", Cgroup: "system.slice/ssh.service"},
		{Kind: "container", Runtime: "podman", ID: podmanID[:12], Name: "research-agent", Cgroup: "machine.slice/libpod-" + podmanID + ".scope"},
		{Kind: "container", Runtime: "podman", ID: unnamed[:12], Cgroup: "machine.slice/libpod-" + unnamed + ".scope"},
		{Kind: "container", Runtime: "docker", ID: dockerID[:12], Name: "support-bot", Cgroup: "system.slice/docker-" + dockerID + ".scope"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d units: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v want %+v", i, got[i], want[i])
		}
	}

	// no runtime files: containers still listed, without names
	got = hostUnits(dirs, unitSources{dockerDir: "/nonexistent", podmanJSON: "/nonexistent"})
	if len(got) != 5 || got[4].Name != "" {
		t.Fatalf("%+v", got)
	}

	// bounded
	many := make([]cgroups.Dir, 0, unitsMax+10)
	for i := 0; i < unitsMax+10; i++ {
		many = append(many, cgroups.Dir{Rel: "system.slice/s" + strings.Repeat("x", i%50) + string(rune('a'+i%26)) + ".service"})
	}
	if n := len(hostUnits(many, src)); n > unitsMax {
		t.Fatalf("%d units", n)
	}
}

func TestUnitsAreSentWhenChangedOrStale(t *testing.T) {
	d := &Daemon{}
	now := time.Unix(1_800_000_000, 0)
	if u, _ := d.unitsToSend(now); u != nil {
		t.Fatal("sent before the first walk")
	}
	d.units = []client.HostUnit{{Kind: "service", Name: "a.service", Cgroup: "system.slice/a.service"}}
	u, key := d.unitsToSend(now)
	if u == nil || len(*u) != 1 {
		t.Fatal("first list not sent")
	}
	// not delivered (the heartbeat failed): sent again
	if u, _ := d.unitsToSend(now.Add(time.Minute)); u == nil {
		t.Fatal("undelivered list not sent again")
	}
	d.unitsDelivered(key, now)
	if u, _ := d.unitsToSend(now.Add(time.Minute)); u != nil {
		t.Fatal("unchanged list sent again")
	}
	if u, _ := d.unitsToSend(now.Add(unitsResend + time.Second)); u == nil {
		t.Fatal("stale list not refreshed")
	}
	d.units = append(d.units, client.HostUnit{Kind: "service", Name: "b.service", Cgroup: "system.slice/b.service"})
	if u, _ := d.unitsToSend(now.Add(2 * time.Minute)); u == nil || len(*u) != 2 {
		t.Fatal("changed list not sent")
	}
}

// The control plane attaches a listed unit with its cgroup escaped for the
// sensor's patterns (agent_network.literal_pattern): it matches that cgroup
// and nothing else.
func TestAnEscapedUnitMatchesOnlyItself(t *testing.T) {
	for _, c := range []struct{ pattern, cgroup, other string }{
		{`system.slice/foo\\x2dbar.service`, `system.slice/foo\x2dbar.service`, `system.slice/fooxx2dbar.service`},
		{`system.slice/a\*b\?\[c].service`, `system.slice/a*b?[c].service`, `system.slice/aXbY[c].service`},
		{`system.slice/billing-agent.service`, `system.slice/billing-agent.service`, `system.slice/billing-agent.service/x`},
	} {
		p := cgroups.NewPattern(c.pattern, 1)
		if !p.Match(c.cgroup) {
			t.Errorf("%s does not match %s", c.pattern, c.cgroup)
		}
		if p.Match(c.other) {
			t.Errorf("%s matches %s", c.pattern, c.other)
		}
	}
}
