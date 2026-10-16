// Copyright (c) 2026 Lazik Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
)

// statusCmd is the `provenza-sensor status` entry point. It connects to the
// daemon's status socket (read-only), reads a JSON snapshot, and prints it
// either as a human-readable report or as raw JSON for scripts.
func statusCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/provenza-sensor/sensor.json", "path to sensor.json (used to locate the socket)")
	socketPath := fs.String("socket", "", "override the status socket path")
	jsonOut := fs.Bool("json", false, "print the raw JSON snapshot instead of the report")
	cgroupsOnly := fs.Bool("cgroups", false, "print only the cgroup section")
	dnsOnly := fs.Bool("dns", false, "print only the DNS section")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: provenza-sensor status [--json] [--socket PATH] [--cgroups|--dns]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	_ = ctx

	sock := *socketPath
	if sock == "" {
		if cfg, err := config.LoadClient(*cfgPath); err == nil && cfg.RunSocket != "" {
			sock = filepath.Join(filepath.Dir(cfg.RunSocket), "status.sock")
		} else {
			sock = "/run/provenza-sensor/status.sock"
		}
	}

	st, err := fetchStatus(sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provenza-sensor status: %v\n", err)
		os.Exit(1)
	}

	switch {
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
	case *cgroupsOnly:
		printCgroups(os.Stdout, st)
	case *dnsOnly:
		printDNS(os.Stdout, st)
	default:
		printReport(os.Stdout, st)
	}
}

// fetchStatus dials the socket and decodes a single JSON document. A missing
// socket is reported as "sensor is not running" rather than a raw ENOENT.
func fetchStatus(path string) (*Status, error) {
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("the sensor is not running (no %s)", path)
		}
		return nil, fmt.Errorf("connect to %s: %w", path, err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var st Status
	if err := json.NewDecoder(conn).Decode(&st); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	return &st, nil
}

// Status is a mirror of daemon.Status. Kept separate so the CLI has no
// dependency on internal packages it does not otherwise need, and so the
// JSON shape is an explicit contract.
type Status struct {
	Host     HostSection    `json:"host"`
	Config   ConfigSection  `json:"config"`
	Key      KeySection     `json:"key"`
	Hooks    HooksSection   `json:"hooks"`
	Warnings []string       `json:"warnings,omitempty"`
	Errors   []string       `json:"errors,omitempty"`
	Policy   *PolicySection `json:"policy,omitempty"`
	Cgroups  CgroupsSection `json:"cgroups"`
	DNS      []DNSSection   `json:"dns,omitempty"`
	Stats    StatsSection   `json:"stats"`
}

type HostSection struct {
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
	SensorVersion string    `json:"sensor_version"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	PID           int       `json:"pid"`
	UnderSystemd  bool      `json:"under_systemd"`
}

type ConfigSection struct {
	Path         string `json:"path"`
	ProvenzaURL  string `json:"provenza_url"`
	CgroupRoot   string `json:"cgroup_root"`
	AttachCgroup string `json:"attach_cgroup"`
	PinDir       string `json:"pin_dir"`
	StateDir     string `json:"state_dir"`
	RunSocket    string `json:"run_socket"`
	RunGroup     string `json:"run_group"`
	RingBytes    uint32 `json:"ring_bytes"`
}

type KeySection struct {
	File    string `json:"file"`
	Masked  string `json:"masked"`
	Present bool   `json:"present"`
	Mode    string `json:"mode,omitempty"`
}

type HooksSection struct {
	Attached []string `json:"attached"`
	LSM      bool     `json:"lsm"`
	Mkdir    bool     `json:"mkdir"`
}

type PolicySection struct {
	Version          string           `json:"version"`
	RefreshSeconds   int              `json:"refresh_seconds"`
	HeartbeatSeconds int              `json:"heartbeat_seconds"`
	RefreshedAt      *time.Time       `json:"refreshed_at,omitempty"`
	Workloads        []WorkloadStatus `json:"workloads"`
}

type WorkloadStatus struct {
	ID             uint32   `json:"id"`
	Name           string   `json:"name"`
	AgentID        *int64   `json:"agent_id,omitempty"`
	Mode           string   `json:"mode"`
	DNS            string   `json:"dns"`
	Isolated       bool     `json:"isolated"`
	IsolatedReason string   `json:"isolated_reason,omitempty"`
	CgroupCount    int      `json:"cgroup_count"`
	CgroupPatterns []string `json:"cgroup_patterns,omitempty"`
}

type CgroupsSection struct {
	Governed  int `json:"governed"`
	RunGroups int `json:"run_groups"`
}

type DNSSection struct {
	WorkloadID  uint32     `json:"workload_id"`
	Port        uint16     `json:"port"`
	Total       uint64     `json:"total"`
	Allowed     uint64     `json:"allowed"`
	Denied      uint64     `json:"denied"`
	LastQueryAt *time.Time `json:"last_query_at,omitempty"`
}

type StatsSection struct {
	DroppedEvents uint64 `json:"dropped_events"`
	Allowed       uint64 `json:"allowed"`
	Denied        uint64 `json:"denied"`
	Observed      uint64 `json:"observed"`
}

// ---------------------------------------------------------------- formatting

func printReport(w *os.File, st *Status) {
	fmt.Fprintf(w, "Provenza egress sensor\n\n")

	fmt.Fprintf(w, "Host\n")
	fmt.Fprintf(w, "  hostname       %s\n", st.Host.Hostname)
	fmt.Fprintf(w, "  platform       %s\n", st.Host.OS)
	fmt.Fprintf(w, "  version        %s\n", st.Host.SensorVersion)
	fmt.Fprintf(w, "  uptime         %s\n", humanDuration(time.Duration(st.Host.UptimeSeconds)*time.Second))
	fmt.Fprintf(w, "  pid            %d\n", st.Host.PID)
	fmt.Fprintf(w, "  systemd        %s\n", yesNo(st.Host.UnderSystemd))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Config\n")
	fmt.Fprintf(w, "  provenza_url   %s\n", st.Config.ProvenzaURL)
	fmt.Fprintf(w, "  cgroup_root    %s\n", st.Config.CgroupRoot)
	fmt.Fprintf(w, "  attach_cgroup  %s\n", st.Config.AttachCgroup)
	fmt.Fprintf(w, "  pin_dir        %s\n", st.Config.PinDir)
	fmt.Fprintf(w, "  state_dir      %s\n", st.Config.StateDir)
	fmt.Fprintf(w, "  run_socket     %s\n", st.Config.RunSocket)
	fmt.Fprintf(w, "  run_group      %s\n", st.Config.RunGroup)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Key\n")
	fmt.Fprintf(w, "  file           %s\n", st.Key.File)
	if st.Key.Present {
		fmt.Fprintf(w, "  masked         %s\n", st.Key.Masked)
		fmt.Fprintf(w, "  mode           %s\n", st.Key.Mode)
	} else {
		fmt.Fprintf(w, "  (missing)\n")
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Hooks (%d)\n", len(st.Hooks.Attached))
	if len(st.Hooks.Attached) > 0 {
		sorted := append([]string(nil), st.Hooks.Attached...)
		sort.Strings(sorted)
		for _, line := range wrapList(sorted, 80, "  ") {
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintf(w, "  lsm            %s\n", yesNo(st.Hooks.LSM))
	fmt.Fprintf(w, "  mkdir          %s\n", yesNo(st.Hooks.Mkdir))
	fmt.Fprintln(w)

	if len(st.Warnings) > 0 {
		fmt.Fprintf(w, "Warnings (%d)\n", len(st.Warnings))
		for _, s := range st.Warnings {
			fmt.Fprintf(w, "  ! %s\n", s)
		}
		fmt.Fprintln(w)
	}
	if len(st.Errors) > 0 {
		fmt.Fprintf(w, "Errors (%d)\n", len(st.Errors))
		for _, s := range st.Errors {
			fmt.Fprintf(w, "  x %s\n", s)
		}
		fmt.Fprintln(w)
	}

	if st.Policy != nil {
		fmt.Fprintf(w, "Policy\n")
		fmt.Fprintf(w, "  version        %s\n", st.Policy.Version)
		fmt.Fprintf(w, "  refresh        %ds\n", st.Policy.RefreshSeconds)
		fmt.Fprintf(w, "  heartbeat      %ds\n", st.Policy.HeartbeatSeconds)
		if st.Policy.RefreshedAt != nil {
			fmt.Fprintf(w, "  refreshed_at   %s\n", st.Policy.RefreshedAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintln(w)
		if len(st.Policy.Workloads) == 0 {
			fmt.Fprintf(w, "  Workloads: none\n")
		} else {
			fmt.Fprintf(w, "  Workloads (%d)\n", len(st.Policy.Workloads))
			for _, wl := range st.Policy.Workloads {
				flags := []string{
					"mode=" + wl.Mode,
					"dns=" + wl.DNS,
					fmt.Sprintf("cgroups=%d", wl.CgroupCount),
				}
				if wl.AgentID != nil {
					flags = append(flags, fmt.Sprintf("agent=%d", *wl.AgentID))
				}
				if wl.Isolated {
					flags = append(flags, "isolated="+wl.IsolatedReason)
				}
				fmt.Fprintf(w, "    #%d  %s  [%s]\n", wl.ID, wl.Name, strings.Join(flags, " "))
				for _, p := range wl.CgroupPatterns {
					fmt.Fprintf(w, "         pattern: %s\n", p)
				}
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Cgroups\n")
	fmt.Fprintf(w, "  governed       %d\n", st.Cgroups.Governed)
	fmt.Fprintf(w, "  run groups     %d\n", st.Cgroups.RunGroups)
	fmt.Fprintln(w)

	printDNS(w, st)

	fmt.Fprintf(w, "Traffic\n")
	fmt.Fprintf(w, "  allowed        %d\n", st.Stats.Allowed)
	fmt.Fprintf(w, "  denied         %d\n", st.Stats.Denied)
	fmt.Fprintf(w, "  observed       %d\n", st.Stats.Observed)
	fmt.Fprintf(w, "  dropped events %d\n", st.Stats.DroppedEvents)
}

func printCgroups(w *os.File, st *Status) {
	fmt.Fprintf(w, "Cgroups\n")
	fmt.Fprintf(w, "  governed       %d\n", st.Cgroups.Governed)
	fmt.Fprintf(w, "  run groups     %d\n", st.Cgroups.RunGroups)
	if st.Policy == nil || len(st.Policy.Workloads) == 0 {
		return
	}
	fmt.Fprintf(w, "  by workload\n")
	for _, wl := range st.Policy.Workloads {
		fmt.Fprintf(w, "    #%d %s: %d\n", wl.ID, wl.Name, wl.CgroupCount)
	}
}

func printDNS(w *os.File, st *Status) {
	if len(st.DNS) == 0 {
		fmt.Fprintf(w, "DNS proxy\n")
		fmt.Fprintf(w, "  (no per-workload listeners)\n\n")
		return
	}
	fmt.Fprintf(w, "DNS proxy (%d listeners)\n", len(st.DNS))
	for _, d := range st.DNS {
		last := "never"
		if d.LastQueryAt != nil {
			last = d.LastQueryAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "  workload #%d  port=%d  total=%d allowed=%d denied=%d  last=%s\n",
			d.WorkloadID, d.Port, d.Total, d.Allowed, d.Denied, last)
	}
	fmt.Fprintln(w)
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", h, m)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// wrapList joins items with two spaces, wrapping at width columns. The
// returned slice is the lines to print, each prefixed with indent.
func wrapList(items []string, width int, indent string) []string {
	if len(items) == 0 {
		return nil
	}
	var lines []string
	cur := indent
	for _, it := range items {
		add := it
		if cur != indent {
			add = "  " + it
		}
		if len(cur)+len(add) > width && cur != indent {
			lines = append(lines, cur)
			cur = indent + it
			continue
		}
		cur += add
	}
	if cur != indent {
		lines = append(lines, cur)
	}
	return lines
}
