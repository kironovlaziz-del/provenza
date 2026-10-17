// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Status is the read-only snapshot returned by `provenza-sensor status`
// over the status socket. Everything here is derived from in-memory state;
// nothing blocks on I/O and nothing mutates. It is intentionally narrow:
// no sensor key, no BPF map contents, no raw DNS query names.
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
	DroppedEvents  uint64 `json:"dropped_events"`
	Allowed        uint64 `json:"allowed"`
	Denied         uint64 `json:"denied"`
	Observed       uint64 `json:"observed"`
	AllowedPerMin  uint64 `json:"allowed_per_min"`
	DeniedPerMin   uint64 `json:"denied_per_min"`
	ObservedPerMin uint64 `json:"observed_per_min"`
}

// maskKey returns the display form of a sensor key: the pvz_sensor_ prefix
// plus the first eight hex characters, then an ellipsis. If the key is
// shorter than the prefix (should not happen), it is returned unchanged.
func maskKey(key string) string {
	const prefix = "pvz_sensor_"
	const keep = 8
	key = trimSpace(key)
	if len(key) <= len(prefix)+keep {
		return key
	}
	return key[:len(prefix)+keep] + "..."
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

// snapshot builds a Status from the current in-memory state under the
// daemon lock. It must stay quick: no I/O, no fs walks.
func (d *Daemon) snapshot() Status {
	d.mu.Lock()
	policy := d.policy
	cgByWid := map[uint32]int{}
	runGroups := 0
	for _, wid := range d.cgWid {
		cgByWid[wid]++
		if wid == 0 {
			runGroups++
		}
	}
	startTime := d.startTime
	lastPolicyAt := d.lastPolicyAt
	d.mu.Unlock()

	host, _ := os.Hostname()

	st := Status{
		Host: HostSection{
			Hostname:      host,
			OS:            runtime.GOOS + "/" + runtime.GOARCH,
			SensorVersion: d.version,
			StartedAt:     startTime,
			UptimeSeconds: int64(time.Since(startTime).Seconds()),
			PID:           os.Getpid(),
			UnderSystemd:  os.Getenv("INVOCATION_ID") != "",
		},
		Config: ConfigSection{
			Path:         d.cfgPath,
			ProvenzaURL:  d.cfg.ProvenzaURL,
			CgroupRoot:   d.cfg.CgroupRoot,
			AttachCgroup: d.cfg.AttachCgroup,
			PinDir:       d.cfg.PinDir,
			StateDir:     d.cfg.StateDir,
			RunSocket:    d.cfg.RunSocket,
			RunGroup:     d.cfg.RunGroup,
			RingBytes:    d.cfg.RingBytes,
		},
		Key: keySection(d.cfg.KeyFile),
		Hooks: HooksSection{
			Attached: append([]string(nil), d.kernel.Hooks...),
			LSM:      d.kernel.LSM,
			Mkdir:    d.kernel.Mkdir,
		},
		Warnings: append([]string(nil), d.kernel.Notes...),
		DNS:      d.dns.stats(cgByWid),
		Stats:    d.statsAndRates(),
	}

	cgroups := CgroupsSection{RunGroups: runGroups}
	for _, n := range cgByWid {
		cgroups.Governed += n
	}
	st.Cgroups = cgroups

	if policy != nil {
		ps := &PolicySection{
			Version:          policy.Version,
			RefreshSeconds:   policy.RefreshSeconds,
			HeartbeatSeconds: policy.HeartbeatSeconds,
			Workloads:        make([]WorkloadStatus, 0, len(policy.Workloads)),
		}
		if !lastPolicyAt.IsZero() {
			t := lastPolicyAt
			ps.RefreshedAt = &t
		}
		for _, w := range policy.Workloads {
			ws := WorkloadStatus{
				ID:             w.ID,
				Name:           w.Name,
				Mode:           w.Mode,
				DNS:            w.DNS,
				Isolated:       w.Isolated,
				CgroupCount:    cgByWid[w.ID],
				CgroupPatterns: append([]string(nil), w.CgroupPatterns...),
			}
			if w.IsolatedReason != nil {
				ws.IsolatedReason = *w.IsolatedReason
			}
			if w.AgentID != nil {
				v := *w.AgentID
				ws.AgentID = &v
			}
			ps.Workloads = append(ps.Workloads, ws)
		}
		st.Policy = ps
	}

	return st
}

// keySection reads the sensor key file for its mode and a masked form of
// the key. The full key never appears in Status.
func keySection(path string) KeySection {
	ks := KeySection{File: path}
	if path == "" {
		return ks
	}
	st, err := os.Stat(path)
	if err != nil {
		return ks
	}
	ks.Present = true
	ks.Mode = st.Mode().Perm().String()
	raw, err := os.ReadFile(path)
	if err != nil {
		return ks
	}
	ks.Masked = maskKey(string(raw))
	return ks
}

// statusSocketPath is where the daemon listens for status clients: next to
// the run socket, so a change to run_socket in sensor.json moves both.
func (d *Daemon) statusSocketPath() string {
	if d.cfg.RunSocket == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(d.cfg.RunSocket), "status.sock")
}

// startStatusServer listens on status.sock. It is started by Run after the
// kernel is attached, and closed on shutdown.
func (d *Daemon) startStatusServer() error {
	path := d.statusSocketPath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if d.cfg.RunGroup != "" {
		if err := chownToGroup(path, d.cfg.RunGroup); err != nil {
			slog.Warn("chown status socket", "err", err)
		}
		_ = os.Chmod(path, 0o660)
	}
	d.status = &statusServer{l: l, d: d}
	go d.status.serve()
	return nil
}

type statusServer struct {
	l net.Listener
	d *Daemon
}

func (s *statusServer) close() {
	_ = s.l.Close()
	_ = os.Remove(s.d.statusSocketPath())
}

func (s *statusServer) serve() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

// handle answers one status request. There is exactly one operation
// ("status"), so a request body is not read; the response is a JSON
// document of the current snapshot. No mutation happens here.
func (s *statusServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	enc := json.NewEncoder(conn)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.d.snapshot()); err != nil {
		slog.Warn("status: encode", "err", err)
	}
}
