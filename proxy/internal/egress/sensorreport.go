// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// On a host with the egress sensor (docs/pvp/edge.md, section 5) the proxy
// runs through `provenza-sensor --proxy run`, which lets it out only while it
// runs a pinned binary with a pinned configuration. The binary the sensor
// hashes itself; the configuration only the proxy knows - it tells the
// sensor the SHA-256 of the file it read, on the sensor's run socket
// (PROVENZA_SENSOR_SOCKET). Being the pinned binary, its word counts; run
// with anything else, it is not let out.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// SensorSocketEnv names the sensor's run socket, set by `provenza-sensor --proxy run`.
const SensorSocketEnv = "PROVENZA_SENSOR_SOCKET"

// ReportConfig tells the sensor the configuration this proxy read.
func ReportConfig(socket, sha string) error {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("the sensor's run socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(map[string]string{"proxy_config": sha}); err != nil {
		return err
	}
	var out struct {
		Cgroup string `json:"cgroup"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&out); err != nil {
		return fmt.Errorf("the sensor did not answer: %w", err)
	}
	if out.Error != "" {
		return errors.New(out.Error)
	}
	return nil
}
