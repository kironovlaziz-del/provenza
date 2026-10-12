// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

// Keys, hashes and signatures - the server's rules (docs/agent-signing.md):
//
//	content hash  SHA-256 hex of the canonical form
//	fingerprint   "SHA256:" + unpadded base64 of SHA-256 over the raw Ed25519
//	              key, followed by the raw ML-DSA-65 key for a hybrid key
//	hybrid        Ed25519 AND ML-DSA-65 over the same bytes; the ML-DSA private key
//	              is its 32-byte FIPS 204 seed (the Python and JS SDKs' form)

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

var b64 = base64.StdEncoding

// ContentHash is the SHA-256 hex of the canonical form of v.
func ContentHash(v any) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:]), nil
}

// Fingerprint of a key (base64 public keys; pq may be empty).
func Fingerprint(publicKey, pqPublicKey string) (string, error) {
	raw, err := b64.DecodeString(publicKey)
	if err != nil {
		return "", err
	}
	if pqPublicKey != "" {
		pq, err := b64.DecodeString(pqPublicKey)
		if err != nil {
			return "", err
		}
		raw = append(raw, pq...)
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + strings.TrimRight(b64.EncodeToString(sum[:]), "="), nil
}

// Keys are an agent's signing keys, base64 of the raw keys (ML-DSA: its seed).
type Keys struct {
	PrivateKey   string
	PublicKey    string
	PQPrivateKey string // empty: not hybrid
	PQPublicKey  string
}

// GenerateKeys makes a new key pair here - private keys never leave the agent.
func GenerateKeys(hybrid bool) (Keys, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, err
	}
	k := Keys{PrivateKey: b64.EncodeToString(priv.Seed()), PublicKey: b64.EncodeToString(pub)}
	if hybrid {
		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return Keys{}, fmt.Errorf("provenza: ML-DSA-65: %w", err)
		}
		k.PQPrivateKey = b64.EncodeToString(sk.Bytes())
		k.PQPublicKey = b64.EncodeToString(sk.PublicKey().Bytes())
	}
	return k, nil
}

// Hybrid tells whether the keys include ML-DSA-65.
func (k Keys) Hybrid() bool { return k.PQPublicKey != "" }

// Fingerprint of these keys.
func (k Keys) Fingerprint() string {
	fp, _ := Fingerprint(k.PublicKey, k.PQPublicKey)
	return fp
}

// Sign signs the canonical form of payload: (Ed25519, ML-DSA-65 or "") in base64.
func (k Keys) Sign(payload any) (string, string, error) {
	msg, err := Canonical(payload)
	if err != nil {
		return "", "", err
	}
	seed, err := b64.DecodeString(k.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", "", fmt.Errorf("provenza: bad Ed25519 private key")
	}
	sig := b64.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(msg)))
	pq := ""
	if k.PQPrivateKey != "" {
		pqSeed, err := b64.DecodeString(k.PQPrivateKey)
		if err != nil {
			return "", "", err
		}
		sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), pqSeed)
		if err != nil {
			return "", "", fmt.Errorf("provenza: ML-DSA-65 key: %w", err)
		}
		s, err := sk.Sign(nil, []byte(msg), nil)
		if err != nil {
			return "", "", err
		}
		pq = b64.EncodeToString(s)
	}
	return sig, pq, nil
}

// verifySignatures checks Ed25519 and, for a hybrid key, ML-DSA-65 over the
// canonical form of payload (AND, never OR).
func verifySignatures(payload any, sig, pqSig, pub, pqPub string) bool {
	msg, err := Canonical(payload)
	if err != nil {
		return false
	}
	pk, err1 := b64.DecodeString(pub)
	s, err2 := b64.DecodeString(sig)
	if err1 != nil || err2 != nil || len(pk) != ed25519.PublicKeySize || !ed25519.Verify(pk, []byte(msg), s) {
		return false
	}
	if pqPub == "" {
		return true
	}
	pqk, err1 := b64.DecodeString(pqPub)
	ps, err2 := b64.DecodeString(pqSig)
	if err1 != nil || err2 != nil {
		return false
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pqk)
	return err == nil && mldsa.Verify(key, []byte(msg), ps, nil) == nil
}
