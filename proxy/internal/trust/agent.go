// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

// The agent's own signed action.request (docs/pvp/spec.md 3.1), checked by
// the enforcement point itself: the agent's key, whose fingerprint the
// signed manifest must name, signed exactly this action, recently, once.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	requestMaxAge = 300 * time.Second
	requestSkew   = 30 * time.Second
)

// SignedRequest is what an agent sends the proxy (X-Provenza-Request): its
// action.request payload, the signature(s) and its public key(s).
type SignedRequest struct {
	Payload     map[string]any
	Signature   string
	PQSignature string
	PublicKey   string
	PQPublicKey string
}

// ParseSignedRequest reads the header value: base64url of the JSON
// {"payload", "signature", "pq_signature"?, "public_key", "pq_public_key"?}.
func ParseSignedRequest(header string) (*SignedRequest, error) {
	raw, err := b64url(header)
	if err != nil || len(raw) > 64*1024 {
		return nil, errors.New("the signed request is not base64url")
	}
	v, err := parseJSON(raw)
	if err != nil {
		return nil, errors.New("the signed request is not JSON")
	}
	m := obj(v)
	r := &SignedRequest{Payload: obj(m["payload"]), Signature: str(m["signature"]), PQSignature: str(m["pq_signature"]),
		PublicKey: str(m["public_key"]), PQPublicKey: str(m["pq_public_key"])}
	if r.Payload == nil || r.Signature == "" || r.PublicKey == "" {
		return nil, errors.New("the signed request lacks its payload, signature or key")
	}
	return r, nil
}

// KeyFingerprint: SHA256:<unpadded base64 of SHA-256 over the raw Ed25519 key,
// followed by the raw ML-DSA-65 key for a hybrid key> - as the manifest names it.
func KeyFingerprint(pub, pq string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", errors.New("bad Ed25519 public key")
	}
	if pq != "" {
		p, err := base64.StdEncoding.DecodeString(pq)
		if err != nil {
			return "", errors.New("bad ML-DSA public key")
		}
		raw = append(raw, p...)
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// Nonces remembers the nonces of accepted requests for their lifetime.
type Nonces struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewNonces() *Nonces { return &Nonces{seen: map[string]time.Time{}} }

func (n *Nonces) use(key string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, t := range n.seen {
		if now.Sub(t) > requestMaxAge+requestSkew {
			delete(n.seen, k)
		}
	}
	if _, dup := n.seen[key]; dup {
		return false
	}
	n.seen[key] = now
	return true
}

// Verify checks the request for this action: type, agent, action type, tool,
// input hash; fresh; the Ed25519 signature over its canonical text (the
// ML-DSA half of a hybrid key is checked by the server, which has it); the
// nonce not seen before. Returns the agent's key fingerprint.
func (r *SignedRequest) Verify(actionType, tool, inputSHA256 string, nonces *Nonces, now time.Time) (string, error) {
	p := r.Payload
	if str(p["type"]) != "action.request" || str(p["action_type"]) != actionType || str(p["tool_name"]) != tool ||
		str(p["input_sha256"]) != inputSHA256 {
		return "", errors.New("the signed request is for another action")
	}
	issued, ok := num(p["issued_at"])
	if !ok {
		return "", errors.New("the signed request has no time")
	}
	age := now.Sub(time.Unix(issued, 0))
	if age > requestMaxAge || age < -requestSkew {
		return "", errors.New("the signed request is too old (or from the future)")
	}
	if !verifyEd25519(r.PublicKey, r.Signature, p) {
		return "", errors.New("the agent's signature does not verify")
	}
	if r.PQPublicKey != "" && r.PQSignature == "" {
		return "", errors.New("a hybrid key without its ML-DSA signature")
	}
	fp, err := KeyFingerprint(r.PublicKey, r.PQPublicKey)
	if err != nil {
		return "", err
	}
	nonce := str(p["nonce"])
	if nonce == "" || !nonces.use(canonText(p["agent_id"])+"/"+nonce, now) {
		return "", errors.New("the signed request was already used")
	}
	return fp, nil
}

// AgentID of the request (parsed JSON number).
func (r *SignedRequest) AgentID() (int64, bool) { return num(r.Payload["agent_id"]) }
