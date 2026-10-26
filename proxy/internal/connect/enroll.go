// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package connect

// Enrollment with an administrator's one-time token, as the SDKs and the
// browser do it (backend/app/services/enrollment.py): the agent's keys are
// made here and never leave this machine; the server gets the public keys and
// a signature over its fresh challenge (proof of possession), and answers
// with the agent's id and API key. The identity file is written mode 600.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

const enrollType = "provenza.agent.enroll"

// Identity: the agent's identity file (provenza-agent.json), as the
// interface's browser enrollment writes it.
type Identity struct {
	Server         string `json:"server"`
	AgentID        int64  `json:"agent_id"`
	APIKey         string `json:"api_key"`
	PrivateKey     string `json:"private_key"`
	PublicKey      string `json:"public_key"`
	PQPrivateKey   string `json:"pq_private_key,omitempty"`
	PQPublicKey    string `json:"pq_public_key,omitempty"`
	KeyFingerprint string `json:"key_fingerprint"`
}

// EnrollOptions of one enrollment.
type EnrollOptions struct {
	Server string // https://provenza.example.com
	Token  string // pvz_enr_...
	Name   string // the agent's name, when the token's template has none
	Hybrid bool   // Ed25519 + ML-DSA-65 even when not required
	Path   string // where the identity file goes
	Client *http.Client
}

type challengeOut struct {
	EnrollmentID  int64  `json:"enrollment_id"`
	OrgID         int64  `json:"org_id"`
	Purpose       string `json:"purpose"`
	Challenge     string `json:"challenge"`
	Name          string `json:"name"`
	RequireHybrid bool   `json:"require_hybrid"`
	AgentID       *int64 `json:"agent_id"`
}

type enrollOut struct {
	AgentID        int64  `json:"agent_id"`
	Name           string `json:"name"`
	APIKey         string `json:"api_key"`
	KeyFingerprint string `json:"key_fingerprint"`
	Purpose        string `json:"purpose"`
}

// Enroll: the agent enrolled (or re-keyed) with the token; its identity written to o.Path.
func Enroll(o EnrollOptions) (*Identity, string, error) {
	server, err := serverURL(o.Server)
	if err != nil {
		return nil, "", err
	}
	if !strings.HasPrefix(o.Token, "pvz_enr_") {
		return nil, "", errors.New("the token starts with pvz_enr_ (Agents -> Connect, or an enrollment token)")
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	var ch challengeOut
	if err := post(client, server+"/api/v1/agent-enrollment/challenge", map[string]any{"token": o.Token}, &ch); err != nil {
		return nil, "", err
	}
	name := ch.Name
	if name == "" && ch.Purpose == "new" {
		name = o.Name // a new key for an existing agent keeps its name
	}
	if ch.Purpose == "new" && name == "" {
		return nil, "", errors.New("the token names no agent: give it a name (--name)")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	id := &Identity{Server: server, PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()),
		PublicKey: base64.StdEncoding.EncodeToString(pub)}
	var pqKey *mldsa.PrivateKey
	if ch.RequireHybrid || o.Hybrid {
		if pqKey, err = mldsa.GenerateKey(mldsa.MLDSA65()); err != nil {
			return nil, "", err
		}
		id.PQPrivateKey = base64.StdEncoding.EncodeToString(pqKey.Bytes())
		id.PQPublicKey = base64.StdEncoding.EncodeToString(pqKey.PublicKey().Bytes())
	}
	var pqPub any // null in the statement for an Ed25519-only key
	if id.PQPublicKey != "" {
		pqPub = id.PQPublicKey
	}
	statement := map[string]any{"type": enrollType, "v": 1, "challenge": ch.Challenge, "org_id": ch.OrgID,
		"enrollment_id": ch.EnrollmentID, "public_key": id.PublicKey, "pq_public_key": pqPub, "name": name}
	msg, err := canon.Bytes(statement)
	if err != nil {
		return nil, "", err
	}
	body := map[string]any{"token": o.Token, "public_key": id.PublicKey, "name": name, "challenge": ch.Challenge,
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))}
	if pqKey != nil {
		sig, err := pqKey.Sign(nil, msg, nil)
		if err != nil {
			return nil, "", err
		}
		body["pq_public_key"] = id.PQPublicKey
		body["pq_signature"] = base64.StdEncoding.EncodeToString(sig)
	}
	var res enrollOut
	if err := post(client, server+"/api/v1/agent-enrollment/enroll", body, &res); err != nil {
		return nil, "", err
	}
	id.AgentID, id.APIKey, id.KeyFingerprint = res.AgentID, res.APIKey, res.KeyFingerprint
	if err := writeIdentity(o.Path, id); err != nil {
		return nil, "", fmt.Errorf("agent #%d is enrolled, but its identity could not be saved: %w", id.AgentID, err)
	}
	return id, res.Purpose, nil
}

func serverURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("the Provenza address is not an http(s) URL of its root: %q", raw)
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return "", errors.New("the Provenza address must be https (the API key travels back over it)")
	}
	return u.Scheme + "://" + u.Host, nil
}

func loopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func post(c *http.Client, endpoint string, in, out any) error {
	raw, _ := json.Marshal(in)
	resp, err := c.Post(endpoint, "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("Provenza is not reachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Detail any `json:"detail"`
		}
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("Provenza refused (HTTP %d): %v", resp.StatusCode, describe(e.Detail, data))
	}
	return json.Unmarshal(data, out)
}

var hints = map[string]string{
	"enrollment.invalid_token": "the token is unknown, used, revoked or expired - get a new command in Agents -> Connect",
	"enrollment.bad_challenge": "the challenge expired - run the command again",
	"agent.pq_required":        "this agent needs a hybrid key",
}

func describe(detail any, raw []byte) string {
	code := ""
	switch d := detail.(type) {
	case string:
		code = d
	case map[string]any:
		code, _ = d["code"].(string)
	}
	if h, ok := hints[code]; ok {
		return h
	}
	if code != "" {
		return code
	}
	if len(raw) > 200 {
		raw = raw[:200]
	}
	return strings.TrimSpace(string(raw))
}

// writeIdentity: mode 600, atomically; an identity already there is kept as <file>.<time>.old.
func writeIdentity(path string, id *Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, fmt.Sprintf("%s.%d.old", path, time.Now().Unix())); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
