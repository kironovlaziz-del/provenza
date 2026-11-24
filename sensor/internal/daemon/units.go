// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

// What runs on this host that an agent could be: its systemd services and
// its containers, by cgroup. The heartbeat carries the list, so an
// administrator attaches an agent to "the service it runs as" with a click
// on the agent's page (docs/egress-lockdown.md, "The agent's network")
// instead of starting it through `provenza-sensor run`.
//
// Only names leave the host: the unit or container name and its cgroup
// path - no command lines, no environment, nothing from inside the
// processes. Rootless containers (under /home) are not listed.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/cgroups"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
)

const (
	unitsMax = 500
	// the list is sent when it changed, and at least this often
	unitsResend = 10 * time.Minute
	// a container runtime's file read for names, at most
	containerFileMax = 8 << 20
)

var (
	// system.slice/<name>.service: a system service (Quadlet containers included)
	reService = regexp.MustCompile(`^system\.slice/([^/]+\.service)$`)
	// a Docker container (systemd cgroup driver) or a rootful Podman one
	reDocker = regexp.MustCompile(`^system\.slice/docker-([0-9a-f]{64})\.scope$`)
	rePodman = regexp.MustCompile(`^machine\.slice/libpod-([0-9a-f]{64})\.scope$`)
)

// where container runtimes keep their containers' names (tests use their own)
type unitSources struct {
	dockerDir  string // /var/lib/docker/containers/<id>/config.v2.json
	podmanJSON string // containers/storage's list of containers
}

var realUnitSources = unitSources{
	dockerDir:  "/var/lib/docker/containers",
	podmanJSON: "/var/lib/containers/storage/overlay-containers/containers.json",
}

// hostUnits: the services and containers among the host's cgroups.
func hostUnits(dirs []cgroups.Dir, src unitSources) []client.HostUnit {
	var podmanNames map[string]string
	out := make([]client.HostUnit, 0, 64)
	for _, dir := range dirs {
		if m := reService.FindStringSubmatch(dir.Rel); m != nil {
			out = append(out, client.HostUnit{Kind: "service", Name: m[1], Cgroup: dir.Rel})
		} else if m := reDocker.FindStringSubmatch(dir.Rel); m != nil {
			out = append(out, client.HostUnit{Kind: "container", Runtime: "docker", ID: m[1][:12],
				Name: dockerName(src.dockerDir, m[1]), Cgroup: dir.Rel})
		} else if m := rePodman.FindStringSubmatch(dir.Rel); m != nil {
			if podmanNames == nil {
				podmanNames = readPodmanNames(src.podmanJSON)
			}
			out = append(out, client.HostUnit{Kind: "container", Runtime: "podman", ID: m[1][:12],
				Name: podmanNames[m[1]], Cgroup: dir.Rel})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind > out[j].Kind // services first
		}
		return out[i].Cgroup < out[j].Cgroup
	})
	if len(out) > unitsMax {
		out = out[:unitsMax]
	}
	return out
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, containerFileMax))
}

// dockerName: the container's name from Docker's own record of it, or "".
func dockerName(dir, id string) string {
	b, err := readLimited(filepath.Join(dir, id, "config.v2.json"))
	if err != nil {
		return ""
	}
	var c struct {
		Name string `json:"Name"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return cleanName(strings.TrimPrefix(c.Name, "/"))
}

// readPodmanNames: container id -> name, from containers/storage.
func readPodmanNames(path string) map[string]string {
	out := map[string]string{}
	b, err := readLimited(path)
	if err != nil {
		return out
	}
	var list []struct {
		ID    string   `json:"id"`
		Names []string `json:"names"`
	}
	if json.Unmarshal(b, &list) != nil {
		return out
	}
	for _, c := range list {
		if len(c.Names) > 0 {
			out[c.ID] = cleanName(c.Names[0])
		}
	}
	return out
}

// a container name as the heartbeat carries it: printable, bounded
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// noteUnits keeps the latest list (from the cgroup walk).
func (d *Daemon) noteUnits(dirs []cgroups.Dir) {
	u := hostUnits(dirs, realUnitSources)
	d.mu.Lock()
	d.units = u
	d.mu.Unlock()
}

// unitsToSend: the list for this heartbeat and its key, or nil when the
// last one delivered is the same and recent (the control plane keeps what
// it had).
func (d *Daemon) unitsToSend(now time.Time) (*[]client.HostUnit, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.units == nil {
		return nil, ""
	}
	b, _ := json.Marshal(d.units)
	key := string(b)
	if key == d.unitsSent && now.Sub(d.unitsSentAt) < unitsResend {
		return nil, ""
	}
	u := append([]client.HostUnit{}, d.units...)
	return &u, key
}

// unitsDelivered: the heartbeat carrying the list with this key went through.
func (d *Daemon) unitsDelivered(key string, now time.Time) {
	if key == "" {
		return
	}
	d.mu.Lock()
	d.unitsSent, d.unitsSentAt = key, now
	d.mu.Unlock()
}
