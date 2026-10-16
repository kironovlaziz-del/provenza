// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Commands the control plane can queue for this sensor: detach, restart,
// dump-state. Every command is signed by the organization's Ed25519 key
// and verified before anything happens; if a check fails the command is
// dropped and the failure is logged. There is no shell, no generic
// execution - only the three behaviours below, whichever way the command
// arrived.

package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
)

// canonicalBytes is the exact byte sequence a command signature covers.
//
// The field order in client.CommandPayload is alphabetical, matching the
// RFC 8785 JCS canonicalization the control plane uses. encoding/json
// writes struct fields in declaration order, so marshal here produces the
// same bytes as canonical_text on the Python side. The pinned string in
// commands_test.go guards this pairing.
func canonicalBytes(p client.CommandPayload) ([]byte, error) {
	return json.Marshal(p)
}

// verifyCommandSignature reports whether sig is a valid Ed25519 signature
// over the canonical form of p, under pub.
func verifyCommandSignature(pub ed25519.PublicKey, p client.CommandPayload, sig string) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	canonical, err := canonicalBytes(p)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, canonical, raw)
}

// loadSigningKey reads the base64 Ed25519 public key enroll wrote. The
// file is 0644: it is public, and the sensor's own service account is the
// only one that needs to read it.
func loadSigningKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("no signing key file configured")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s: %d bytes, want %d", path, len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

// loadSensorID reads the integer id enroll wrote: this sensor's own id,
// which every command payload must name.
func loadSensorID(path string) (int, error) {
	if path == "" {
		return 0, errors.New("no sensor id file configured")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var id int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &id); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	if id <= 0 {
		return 0, fmt.Errorf("%s: id must be positive", path)
	}
	return id, nil
}

// handleCommands runs what the control plane returned for a heartbeat.
// Each command is checked on its own; a failure logs and drops, it does
// not stop the others. Order is the backend's (oldest first).
func (d *Daemon) handleCommands(ctx context.Context, cmds []client.Command) {
	for _, c := range cmds {
		if err := d.handleOneCommand(ctx, c); err != nil {
			slog.Warn("command refused", "id", c.ID, "kind", c.Kind, "err", err)
		}
	}
}

// handleOneCommand verifies a command and dispatches it. Every check
// happens before any side effect; the signature is the only gate on what
// the command may do, and the three behaviours below are the only things
// it may trigger.
func (d *Daemon) handleOneCommand(ctx context.Context, c client.Command) error {
	if d.signingKey == nil {
		return errors.New("no signing key on this host (re-run enroll)")
	}
	if d.sensorID == 0 {
		return errors.New("no sensor id on this host (re-run enroll)")
	}
	if c.Payload.SensorID != d.sensorID {
		return fmt.Errorf("command is for sensor %d, this is %d",
			c.Payload.SensorID, d.sensorID)
	}
	if c.Payload.ID != c.ID {
		return fmt.Errorf("payload id %d does not match command id %d",
			c.Payload.ID, c.ID)
	}
	if c.Payload.Kind != c.Kind {
		return fmt.Errorf("payload kind %q does not match command kind %q",
			c.Payload.Kind, c.Kind)
	}
	expiresAt, err := time.Parse(time.RFC3339, c.Payload.ExpiresAt)
	if err != nil {
		return fmt.Errorf("bad expires_at: %w", err)
	}
	if time.Now().After(expiresAt) {
		return errors.New("command expired")
	}
	if !verifyCommandSignature(d.signingKey, c.Payload, c.Signature) {
		return errors.New("bad signature")
	}

	slog.Info("command accepted", "id", c.ID, "kind", c.Kind)

	// Acknowledge before doing anything: a detach that stops the daemon
	// must be visible on the control plane even though no "done" follows.
	if err := d.client.AckCommand(ctx, c.ID, "executing", nil, ""); err != nil {
		slog.Warn("ack executing", "id", c.ID, "err", err)
	}

	switch c.Kind {
	case "dump-state":
		return d.execDumpState(ctx, c)
	case "restart":
		return d.execRestart(ctx, c)
	case "detach":
		return d.execDetach(ctx, c)
	default:
		// The backend refuses unknown kinds; this only fires when a newer
		// backend sent a kind this build does not know.
		_ = d.client.AckCommand(ctx, c.ID, "failed", nil, "unknown kind: "+c.Kind)
		return fmt.Errorf("unknown command kind %q", c.Kind)
	}
}

// execDumpState answers with the sensor's own snapshot - the same content
// `provenza-sensor status --json` prints locally.
func (d *Daemon) execDumpState(ctx context.Context, c client.Command) error {
	result := d.snapshot()
	if err := d.client.AckCommand(ctx, c.ID, "done", result, ""); err != nil {
		return fmt.Errorf("ack done: %w", err)
	}
	return nil
}

// execRestart asks systemd to restart the unit. The call is asynchronous:
// waiting for systemctl would deadlock, because systemctl waits for this
// process to exit and this process waits for systemctl to return.
func (d *Daemon) execRestart(ctx context.Context, c client.Command) error {
	// "Done" means "the daemon accepted the restart". A new process will
	// be up in a second; whether it succeeds is what the next heartbeat
	// shows on the control plane.
	if err := d.client.AckCommand(ctx, c.ID, "done", nil, ""); err != nil {
		slog.Warn("ack done", "id", c.ID, "err", err)
	}
	cmd := exec.Command("systemctl", "restart", "provenzasensor")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("systemctl restart: %w", err)
	}
	// Do not Wait: systemd will send us SIGTERM shortly, our normal
	// shutdown follows.
	return nil
}

// execDetach removes the sensor from this host. The ack precedes the
// uninstall because uninstall deletes the key file the next ack would
// need; if uninstall fails halfway, the admin sees "done" and can issue
// another command.
func (d *Daemon) execDetach(ctx context.Context, c client.Command) error {
	if err := d.client.AckCommand(ctx, c.ID, "done", nil, ""); err != nil {
		slog.Warn("ack done", "id", c.ID, "err", err)
	}
	if err := Uninstall(ctx, d.cfgPath); err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}
	slog.Info("detached by command", "id", c.ID)
	return nil
}
