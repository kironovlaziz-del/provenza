// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

// A command to a sensor that an administrator signed (docs/pvp/edge.md,
// section 5): the administrator's session key signed provenza.sensor.command
// for exactly this sensor and kind, the administrator's passkey certified that
// session key, and that passkey is the one the signed manifest lists for an
// administrator. The server only carries it: it cannot make one.
//
// The rest of this package is a copy of proxy/internal/trust (a server test
// keeps the two identical); this file is the sensor's own.

import (
	"errors"
	"fmt"
	"time"
)

const (
	commandType = "provenza.sensor.command"
	// MaxCommandLife bounds how long a signed command may be valid (the sensor
	// cannot learn that its signer signed out meanwhile).
	MaxCommandLife = 5 * time.Minute
	// clockSkew: how far ahead of this host's clock a command may be issued.
	clockSkew = time.Minute
	adminRole = "admin"
)

// CommandKinds are the commands an administrator can sign for a sensor.
var CommandKinds = map[string]bool{"detach": true, "restart": true, "dump-state": true}

// Command is a verified administrator's command.
type Command struct {
	Kind      string
	Nonce     string
	UserID    string
	ExpiresAt time.Time
	Passkey   string // the fingerprint of the passkey that certified the session
}

// VerifyCommand checks a signed command (the proof the server keeps with it,
// app/services/egress_sensor_commands.py) against the signed manifest, for
// this sensor, at now.
func VerifyCommand(proof map[string]any, manifest map[string]any, sensorID int64, now time.Time) (*Command, error) {
	st, cert := obj(proof["statement"]), obj(obj(proof["certificate"])["statement"])
	if st == nil || cert == nil {
		return nil, errors.New("command: not a signed command")
	}
	if str(st["type"]) != commandType {
		return nil, errors.New("command: not a sensor command")
	}
	if v, _ := num(st["v"]); v != 1 {
		return nil, errors.New("command: unknown statement version")
	}
	if id, ok := num(st["sensor_id"]); !ok || id != sensorID {
		return nil, fmt.Errorf("command: signed for sensor %s, this is %d", canonText(st["sensor_id"]), sensorID)
	}
	kind := str(st["kind"])
	if !CommandKinds[kind] {
		return nil, fmt.Errorf("command: an administrator cannot sign %q", kind)
	}
	nonce := str(st["nonce"])
	if len(nonce) < 16 || len(nonce) > 64 {
		return nil, errors.New("command: no nonce")
	}
	if org, ok := num(manifest["org_id"]); !ok || canonText(st["org_id"]) != canonText(manifest["org_id"]) || org <= 0 {
		return nil, errors.New("command: signed for another organization")
	}
	issued, ok1 := num(st["issued_at"])
	expires, ok2 := num(st["expires_at"])
	if !ok1 || !ok2 || expires <= issued || time.Duration(expires-issued)*time.Second > MaxCommandLife {
		return nil, errors.New("command: bad validity")
	}
	if now.Add(clockSkew).Unix() < issued {
		return nil, errors.New("command: issued in the future (check this host's clock)")
	}
	if now.Unix() >= expires {
		return nil, errors.New("command: expired")
	}

	sessionKey := str(proof["session_public_key"])
	if str(cert["type"]) != "provenza.session.certificate" || str(cert["public_key"]) != sessionKey {
		return nil, errors.New("command: the session certificate is not for the key that signed")
	}
	for _, k := range []string{"org_id", "user_id", "session_id"} {
		if canonText(st[k]) != canonText(cert[k]) {
			return nil, fmt.Errorf("command: signed in another session than the certificate names (%s)", k)
		}
	}
	from, _ := num(cert["not_before"])
	until, _ := num(cert["not_after"])
	if issued < from || issued > until {
		return nil, errors.New("command: signed outside the session's validity")
	}
	if !verifyEd25519(sessionKey, str(proof["signature"]), st) {
		return nil, errors.New("command: the session key's signature does not verify")
	}
	user := canonText(st["user_id"])
	person := obj(obj(manifest["signers"])[user])
	if person == nil {
		return nil, errors.New("command: the signer is not in the signed manifest")
	}
	if str(person["role"]) != adminRole {
		return nil, errors.New("command: the signer is not an administrator in the signed manifest")
	}
	certificate := obj(proof["certificate"])
	key := obj(obj(person["passkeys"])[str(certificate["credential_id"])])
	if key == nil || str(key["public_key"]) != str(obj(proof["passkey"])["public_key"]) {
		return nil, errors.New("command: the administrator's passkey is not in the signed manifest")
	}
	alg, _ := num(key["alg"])
	challenge, err := statementChallenge(cert)
	if err != nil {
		return nil, err
	}
	if err := verifyAssertion(str(key["public_key"]), int(alg), obj(certificate["assertion"]), challenge); err != nil {
		return nil, fmt.Errorf("command: the passkey did not certify the session: %w", err)
	}
	return &Command{Kind: kind, Nonce: nonce, UserID: user, ExpiresAt: time.Unix(expires, 0),
		Passkey: PasskeyFingerprint(str(key["public_key"]))}, nil
}

// ProxyBinaries: the SHA-256 (lowercase hex) of the egress proxy binaries the
// signed manifest lets out of a proxy host.
func ProxyBinaries(manifest map[string]any) map[string]bool {
	out := map[string]bool{}
	list, _ := manifest["proxy_binaries"].([]any)
	for _, v := range list {
		if s := str(v); isSHA256(s) {
			out[s] = true
		}
	}
	return out
}

// ProxyConfigs: the SHA-256 of the egress proxy configurations the signed
// manifest lets a proxy run with (the file's bytes, as the proxy read them).
func ProxyConfigs(manifest map[string]any) map[string]bool {
	out := map[string]bool{}
	list, _ := manifest["proxy_configs"].([]any)
	for _, v := range list {
		if s := str(v); isSHA256(s) {
			out[s] = true
		}
	}
	return out
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
