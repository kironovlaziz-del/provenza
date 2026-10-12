// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

// An agent's identity: agent id and API key, and the keys it signs with -
// generated here, on the agent's side; the server only receives public keys.
// Stored in ~/.config/provenza/agents/<name>.json (mode 600, directory 700,
// written atomically) in the format of the Python and JS SDKs and
// tools/provenza_sign.py. A file other users can read is refused.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Identity of an agent. Server is empty for a standalone (local-only) identity.
type Identity struct {
	Keys    Keys
	Server  string
	AgentID *int64
	APIKey  string
	Name    string
}

type identityFile struct {
	Server         *string `json:"server"`
	AgentID        *int64  `json:"agent_id"`
	APIKey         *string `json:"api_key"`
	Name           *string `json:"name"`
	PrivateKey     string  `json:"private_key"`
	PublicKey      string  `json:"public_key"`
	PQPrivateKey   *string `json:"pq_private_key"`
	PQPublicKey    *string `json:"pq_public_key"`
	KeyFingerprint string  `json:"key_fingerprint"`
	Secrets        string  `json:"secrets,omitempty"`
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// DefaultIdentityPath is ~/.config/provenza/agents/<name>.json ($XDG_CONFIG_HOME respected).
func DefaultIdentityPath(name string) string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	var b strings.Builder
	dash := false
	for _, r := range name {
		ok := r < 128 && (r == '_' || r == '.' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
		if ok {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	slug := strings.Trim(b.String(), "-.")
	if slug == "" {
		slug = "agent"
	}
	return filepath.Join(base, "provenza", "agents", slug+".json")
}

// SaveIdentity writes the identity owner-only and atomically.
func SaveIdentity(id *Identity, path string) error {
	f := identityFile{
		Server: nilIfEmpty(id.Server), AgentID: id.AgentID, APIKey: nilIfEmpty(id.APIKey), Name: nilIfEmpty(id.Name),
		PrivateKey: id.Keys.PrivateKey, PublicKey: id.Keys.PublicKey, PQPrivateKey: nilIfEmpty(id.Keys.PQPrivateKey),
		PQPublicKey: nilIfEmpty(id.Keys.PQPublicKey), KeyFingerprint: id.Keys.Fingerprint(),
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path) // atomic: never half a key file
}

// LoadIdentity reads the identity at path; (nil, nil) when there is none.
func LoadIdentity(path string) (*Identity, error) {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &ConfigError{fmt.Sprintf("cannot read the identity at %s: %v", path, err)}
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, &ConfigError{path + " is readable by other users; chmod 600 it (it holds private keys)"}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigError{fmt.Sprintf("cannot read the identity at %s: %v", path, err)}
	}
	var f identityFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, &ConfigError{fmt.Sprintf("cannot read the identity at %s: %v", path, err)}
	}
	if f.Secrets == "keychain" {
		return nil, &ConfigError{path + " keeps its keys in an OS keychain (Python SDK); the Go SDK cannot read it"}
	}
	if f.PrivateKey == "" || f.PublicKey == "" {
		return nil, &ConfigError{path + " lacks the agent's keys"}
	}
	return &Identity{
		Keys:   Keys{PrivateKey: f.PrivateKey, PublicKey: f.PublicKey, PQPrivateKey: deref(f.PQPrivateKey), PQPublicKey: deref(f.PQPublicKey)},
		Server: deref(f.Server), AgentID: f.AgentID, APIKey: deref(f.APIKey), Name: deref(f.Name),
	}, nil
}

// enroll joins with a one-time enrollment token (provenza.agent.enroll v1).
func enroll(ctx context.Context, c *client, token, name string, hybrid bool) (*Identity, error) {
	ch, err := c.post(ctx, "/agent-enrollment/challenge", map[string]any{"token": token}, false)
	if err != nil {
		return nil, err
	}
	requireHybrid, _ := ch["require_hybrid"].(bool)
	keys, err := GenerateKeys(hybrid || requireHybrid)
	if err != nil {
		return nil, err
	}
	final := strings.TrimSpace(str(ch, "name"))
	if final == "" {
		final = strings.TrimSpace(name)
	}
	statement := map[string]any{
		"type": "provenza.agent.enroll", "v": 1, "challenge": ch["challenge"], "org_id": ch["org_id"],
		"enrollment_id": ch["enrollment_id"], "public_key": keys.PublicKey, "pq_public_key": nilIfEmpty(keys.PQPublicKey),
		"name": final,
	}
	sig, pq, err := keys.Sign(statement)
	if err != nil {
		return nil, err
	}
	res, err := c.post(ctx, "/agent-enrollment/enroll", map[string]any{
		"token": token, "challenge": ch["challenge"], "public_key": keys.PublicKey,
		"pq_public_key": nilIfEmpty(keys.PQPublicKey), "name": nilIfEmpty(final), "signature": sig,
		"pq_signature": nilIfEmpty(pq),
	}, false)
	if err != nil {
		return nil, err
	}
	if fp := str(res, "key_fingerprint"); fp != "" && fp != keys.Fingerprint() {
		return nil, &ConfigError{"the server registered another key than the one generated here"}
	}
	agentName := str(res, "name")
	if agentName == "" {
		agentName = final
	}
	return &Identity{Keys: keys, Server: c.serverURL, AgentID: optInt(res, "agent_id"), APIKey: str(res, "api_key"),
		Name: agentName}, nil
}
