// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type enrollOpts struct {
	URL        string
	Key        string
	KeyFile    string
	ConfigPath string
	CgroupRoot string
	PinDir     string
	StateDir   string
	RunSocket  string
	RunGroup   string
	RingBytes  uint
	NoRestart  bool
}

// enrollCmd is the `provenza-sensor enroll` entry point: it takes the URL
// of the control plane and the sensor key shown once at registration, writes
// /etc/provenza-sensor/{sensor.json,key}, checks the key against the control
// plane, and restarts the service if it is already installed.
func enrollCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	o := enrollOpts{}
	fs.StringVar(&o.URL, "url", "", "control plane URL, e.g. https://provenza.example.com")
	fs.StringVar(&o.Key, "key", "", "sensor key from the Register sensor button (pvz_sensor_...)")
	fs.StringVar(&o.KeyFile, "key-file", "/etc/provenza-sensor/key", "where to write the key")
	fs.StringVar(&o.ConfigPath, "config", "/etc/provenza-sensor/sensor.json", "where to write sensor.json")
	fs.StringVar(&o.CgroupRoot, "cgroup-root", "/sys/fs/cgroup", "cgroup v2 mount")
	fs.StringVar(&o.PinDir, "pin-dir", "/sys/fs/bpf/provenza", "bpffs directory for pinned links")
	fs.StringVar(&o.StateDir, "state-dir", "/var/lib/provenza-sensor", "state directory")
	fs.StringVar(&o.RunSocket, "run-socket", "/run/provenza-sensor/run.sock", "run socket path")
	fs.StringVar(&o.RunGroup, "run-group", "provenza", "group allowed to use the run socket")
	fs.UintVar(&o.RingBytes, "ring-bytes", 262144, "ring buffer size (power of two)")
	fs.BoolVar(&o.NoRestart, "no-restart", false, "do not restart provenzasensor.service after writing the config")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: provenza-sensor enroll --url URL --key pvz_sensor_...")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if err := enroll(ctx, o); err != nil {
		slog.Error("enroll", "err", err)
		os.Exit(1)
	}
}

func enroll(ctx context.Context, o enrollOpts) error {
	if o.URL == "" {
		return errors.New("--url is required (the address you open in the browser)")
	}
	if o.Key == "" {
		return errors.New("--key is required (from Register sensor on the Runtime page)")
	}
	if !strings.HasPrefix(o.Key, "pvz_sensor_") {
		return errors.New("the key must start with pvz_sensor_ (it is shown once when you register the sensor)")
	}
	url := strings.TrimRight(o.URL, "/")

	slog.Info("checking control plane", "url", url)
	if err := pingURL(ctx, url); err != nil {
		return fmt.Errorf("cannot reach %s: %w", url, err)
	}

	slog.Info("checking sensor key")
	if err := verifyKey(ctx, url, o.Key); err != nil {
		return fmt.Errorf("key rejected by %s: %w", url, err)
	}

	if err := os.MkdirAll(filepath.Dir(o.KeyFile), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(o.KeyFile), err)
	}
	if err := os.WriteFile(o.KeyFile, []byte(o.Key+"\n"), 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	slog.Info("wrote key", "path", o.KeyFile)

	cfg := map[string]any{
		"provenza_url":  url,
		"key_file":      o.KeyFile,
		"cgroup_root":   o.CgroupRoot,
		"attach_cgroup": o.CgroupRoot,
		"pin_dir":       o.PinDir,
		"state_dir":     o.StateDir,
		"run_socket":    o.RunSocket,
		"run_group":     o.RunGroup,
		"ring_bytes":    uint32(o.RingBytes),
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := os.WriteFile(o.ConfigPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	slog.Info("wrote config", "path", o.ConfigPath)

	if !o.NoRestart {
		if _, err := exec.LookPath("systemctl"); err == nil {
			if err := exec.CommandContext(ctx, "systemctl", "restart", "provenzasensor").Run(); err != nil {
				slog.Warn("systemctl restart provenzasensor failed (unit may not be installed yet)", "err", err)
			} else {
				slog.Info("restarted provenzasensor.service")
			}
		}
	}
	slog.Info("enrolled", "url", url)
	return nil
}

func pingURL(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/health", nil)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("/health returned %d", resp.StatusCode)
	}
	return nil
}

func verifyKey(ctx context.Context, url, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/api/v1/egress-sensor/config", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Sensor-Key", key)
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNotModified:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("401/403: the key is wrong or the sensor was revoked")
	case http.StatusNotFound:
		return errors.New("404: the control plane does not expose /api/v1/egress-sensor (is the sensor feature deployed?)")
	default:
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}
