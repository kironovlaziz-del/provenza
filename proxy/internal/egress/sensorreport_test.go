// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The configuration's SHA-256 is of the very bytes read, and it goes to the sensor.
func TestTheConfigurationIsReportedToTheSensor(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"server_url": "https://p.example", "state_dir": "` + dir + `"}`)
	path := filepath.Join(dir, "proxy.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if cfg.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("%s", cfg.SHA256)
	}
	sock := filepath.Join(dir, "run.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan string, 2)
	answer := `{"cgroup":"provenza-run/proxy-1"}`
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			var req map[string]string
			_ = json.NewDecoder(c).Decode(&req)
			got <- req["proxy_config"]
			_, _ = c.Write([]byte(answer + "\n"))
			c.Close()
		}
	}()
	if err := ReportConfig(sock, cfg.SHA256); err != nil || <-got != cfg.SHA256 {
		t.Fatal(err)
	}
	answer = `{"error":"configuration x is not a pinned egress proxy configuration"}`
	if err := ReportConfig(sock, cfg.SHA256); err == nil || !strings.Contains(err.Error(), "not a pinned") {
		t.Fatal(err)
	}
	if err := ReportConfig(filepath.Join(dir, "none.sock"), cfg.SHA256); err == nil {
		t.Fatal("no sensor, no error")
	}
}
