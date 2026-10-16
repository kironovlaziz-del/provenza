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
// over the canonical form of p, under pub. Kept for a single-key test;
// production code uses verifyCommandSignatureAny.
func verifyCommandSignature(pub ed25519.PublicKey, p client.CommandPayload, sig string) bool {
	return verifyCommandSignatureAny([]ed25519.PublicKey{pub}, p, sig)
}

// verifyCommandSignatureAny tries each key in order and returns true on the
// first that verifies. The list is small (current key, then the previous
// one during a rotation grace period), so trying them one by one costs
// nothing next to a signature check.
func verifyCommandSignatureAny(pubs []ed25519.PublicKey, p client.CommandPayload, sig string) bool {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	canonical, err := canonicalBytes(p)
	if err != nil {
		return false
	}
	for _, pub := range pubs {
		if len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(pub, canonical, raw) {
			return true
		}
	}
	return false
}

// prevKeyPath and prevUntilPath place the rotation companion files next to
// the active key. A file /x/signing-key.pub has /x/signing-key.prev.pub
// and /x/signing-key.prev.until.
func prevKeyPath(active string) string {
	if strings.HasSuffix(active, ".pub") {
		return strings.TrimSuffix(active, ".pub") + ".prev.pub"
	}
	return active + ".prev.pub"
}

func prevUntilPath(active string) string {
	if strings.HasSuffix(active, ".pub") {
		return strings.TrimSuffix(active, ".pub") + ".prev.until"
	}
	return active + ".prev.until"
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

// loadPreviousSigningKey reads the .prev.pub companion written during a
// rotation. A missing file is not an error: it simply means no rotation
// has ever happened on this host.
func loadPreviousSigningKey(activePath string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(prevKeyPath(activePath))
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", prevKeyPath(activePath), err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s: %d bytes, want %d",
			prevKeyPath(activePath), len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

// loadPreviousValidUntil reads the deadline stored with the previous key.
// A missing file means the previous key has no deadline of its own; a
// missing .prev.pub makes this call irrelevant anyway.
func loadPreviousValidUntil(activePath string) (time.Time, error) {
	raw, err := os.ReadFile(prevUntilPath(activePath))
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", prevUntilPath(activePath), err)
	}
	return t, nil
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
	keys := []ed25519.PublicKey{d.signingKey}
	if d.previousSigningKey != nil {
		if d.previousValidUntil.IsZero() || time.Now().Before(d.previousValidUntil) {
			keys = append(keys, d.previousSigningKey)
		}
	}
	if !verifyCommandSignatureAny(keys, c.Payload, c.Signature) {
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
	case "update-signing-key":
		return d.execUpdateSigningKey(ctx, c)
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

// execUpdateSigningKey swaps the organization's command signing key.
//
// The command itself was signed with the OLD key (that is what the sensor
// currently trusts); the payload carries the new public key and the
// deadline for the old one. On success the sensor writes the new key to
// signing-key.pub, moves the current one to signing-key.prev.pub, and
// stores the deadline in signing-key.prev.until. In memory it flips the
// two keys and records the deadline; verification tries the current key
// first and falls back to the previous one until that deadline passes.
func (d *Daemon) execUpdateSigningKey(ctx context.Context, c client.Command) error {
	newKeyB64 := strings.TrimSpace(c.Payload.NewPublicKey)
	if newKeyB64 == "" {
		_ = d.client.AckCommand(ctx, c.ID, "failed", nil, "empty new_public_key")
		return errors.New("empty new_public_key")
	}
	raw, err := base64.StdEncoding.DecodeString(newKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		_ = d.client.AckCommand(ctx, c.ID, "failed", nil, "bad new_public_key")
		return fmt.Errorf("bad new_public_key: %w", err)
	}
	newKey := ed25519.PublicKey(raw)

	// Read the current key's bytes: they become the previous key, verbatim.
	activeRaw, err := os.ReadFile(d.cfg.SigningPublicKeyFile)
	if err != nil {
		_ = d.client.AckCommand(ctx, c.ID, "failed", nil, "read active key: "+err.Error())
		return fmt.Errorf("read active key: %w", err)
	}

	// Previous valid until (may be empty: no deadline).
	var prevUntil time.Time
	if s := strings.TrimSpace(c.Payload.PreviousValidUntil); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			prevUntil = t
		} else {
			slog.Warn("update-signing-key: bad previous_valid_until", "value", s, "err", err)
		}
	}

	// Write previous key and its deadline, then the new active key. If any
	// of these fail we stop before touching signing-key.pub: a half-written
	// key set is worse than an old one.
	if err := os.WriteFile(prevKeyPath(d.cfg.SigningPublicKeyFile), activeRaw, 0o644); err != nil {
		_ = d.client.AckCommand(ctx, c.ID, "failed", nil, "write prev key: "+err.Error())
		return fmt.Errorf("write prev key: %w", err)
	}
	if !prevUntil.IsZero() {
		if err := os.WriteFile(prevUntilPath(d.cfg.SigningPublicKeyFile),
			[]byte(prevUntil.UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
			_ = d.client.AckCommand(ctx, c.ID, "failed", nil, "write prev deadline: "+err.Error())
			return fmt.Errorf("write prev deadline: %w", err)
		}
	} else {
		_ = os.Remove(prevUntilPath(d.cfg.SigningPublicKeyFile))
	}
	if err := os.WriteFile(d.cfg.SigningPublicKeyFile, []byte(newKeyB64+"\n"), 0o644); err != nil {
		_ = d.client.AckCommand(ctx, c.ID, "failed", nil, "write active key: "+err.Error())
		return fmt.Errorf("write active key: %w", err)
	}

	// Flip in memory only after disk is consistent.
	d.previousSigningKey = d.signingKey
	d.signingKey = newKey
	d.previousValidUntil = prevUntil

	slog.Info("signing key updated",
		"previous_valid_until", prevUntil.UTC().Format(time.RFC3339))

	if err := d.client.AckCommand(ctx, c.ID, "done", nil, ""); err != nil {
		return fmt.Errorf("ack done: %w", err)
	}
	return nil
}
