// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Package config: the sensor's own settings (sensor.json) and the policy it
// receives from Provenza (GET /api/v1/egress-sensor/config).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Settings is /etc/provenza-sensor/sensor.json.
type Settings struct {
	ProvenzaURL  string `json:"provenza_url"`  // https://provenza.example.com
	KeyFile      string `json:"key_file"`      // file holding pvz_sensor_...
	CAFile       string `json:"ca_file"`       // extra CA for Provenza's TLS; "" = system roots
	CgroupRoot   string `json:"cgroup_root"`   // cgroup v2 mount
	AttachCgroup string `json:"attach_cgroup"` // where the programs attach; "" = cgroup_root
	PinDir       string `json:"pin_dir"`       // bpffs directory for pinned links
	StateDir     string `json:"state_dir"`     // last policy, so a restart without Provenza still enforces
	RunSocket    string `json:"run_socket"`    // for `provenza-sensor run`
	RunGroup     string `json:"run_group"`     // group allowed to use it ("" = root only)
	RingBytes    uint32 `json:"ring_bytes"`

	Key string `json:"-"`
}

func Defaults() Settings {
	return Settings{
		KeyFile:    "/etc/provenza-sensor/key",
		CgroupRoot: "/sys/fs/cgroup",
		PinDir:     "/sys/fs/bpf/provenza",
		StateDir:   "/var/lib/provenza-sensor",
		RunSocket:  "/run/provenza-sensor/run.sock",
		RunGroup:   "provenza",
	}
}

// Load reads the settings file and the key. PROVENZA_URL and
// PROVENZA_SENSOR_KEY override the file.
func Load(path string) (Settings, error) {
	s := Defaults()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return s, err
		}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			return s, fmt.Errorf("%s: %w", path, err)
		}
	}
	if v := os.Getenv("PROVENZA_URL"); v != "" {
		s.ProvenzaURL = v
	}
	s.Key = strings.TrimSpace(os.Getenv("PROVENZA_SENSOR_KEY"))
	if s.Key == "" && s.KeyFile != "" {
		data, err := os.ReadFile(s.KeyFile)
		if err != nil {
			return s, fmt.Errorf("sensor key: %w", err)
		}
		s.Key = strings.TrimSpace(string(data))
	}
	if s.AttachCgroup == "" {
		s.AttachCgroup = s.CgroupRoot
	}
	return s, s.validate()
}

func (s Settings) validate() error {
	u, err := url.Parse(s.ProvenzaURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("provenza_url: an http(s) URL is required")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return errors.New("provenza_url: https is required unless Provenza is on this host")
	}
	if !strings.HasPrefix(s.Key, "pvz_sensor_") {
		return errors.New("the sensor key (pvz_sensor_...) is missing or malformed")
	}
	return nil
}

func isLoopback(h string) bool {
	return h == "localhost" || h == "::1" || strings.HasPrefix(h, "127.")
}

// ---------------------------------------------------------------- policy

// Policy is what Provenza sends every sensor of the organization.
type Policy struct {
	Schema           int        `json:"schema"`
	Version          string     `json:"version"`
	RefreshSeconds   int        `json:"refresh_seconds"`
	HeartbeatSeconds int        `json:"heartbeat_seconds"`
	Workloads        []Workload `json:"workloads"`
}

type Workload struct {
	ID             uint32   `json:"id"`
	Name           string   `json:"name"`
	AgentID        *int64   `json:"agent_id"`
	CgroupPatterns []string `json:"cgroup_patterns"`
	RunAsUsers     []string `json:"run_as_users"`
	EgressAllow    []Allow  `json:"egress_allow"`
	IngressAllow   []Allow  `json:"ingress_allow"`
	DNS            string   `json:"dns"`  // off | listed | any
	Mode           string   `json:"mode"` // observe | alert | enforce
	Isolated       bool     `json:"isolated"`
	IsolatedReason *string  `json:"isolated_reason"`
}

// Allow: Dest is a network or a host name (egress; "*.corp.internal" too),
// Source a network (ingress).
type Allow struct {
	Dest      string   `json:"dest,omitempty"`
	Source    string   `json:"source,omitempty"`
	Ports     []int    `json:"ports"`
	Protocols []string `json:"protocols"`
}

const SchemaVersion = 1

func (p *Policy) Check() error {
	if p.Schema != SchemaVersion {
		return fmt.Errorf("policy schema %d: this sensor understands %d (upgrade it)", p.Schema, SchemaVersion)
	}
	seen := map[uint32]bool{}
	for _, w := range p.Workloads {
		if w.ID == 0 || seen[w.ID] {
			return fmt.Errorf("workload id %d: missing or repeated", w.ID)
		}
		seen[w.ID] = true
		switch w.Mode {
		case "observe", "alert", "enforce":
		default:
			return fmt.Errorf("workload %d: unknown mode %q", w.ID, w.Mode)
		}
		switch w.DNS {
		case "off", "listed", "any":
		default:
			return fmt.Errorf("workload %d: unknown dns %q", w.ID, w.DNS)
		}
	}
	return nil
}
