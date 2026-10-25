// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Package trust checks what people signed, without trusting the server:
// policy releases signed by a quorum of administrators' passkeys, and human
// approvals signed with a session key a passkey certified
// (docs/pvp/edge.md, sections 2-3). It is the Go counterpart of
// tools/provenza_audit.py (release, receipt) and app/pvp/signed_policy.py.
package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

const (
	es256 = -7
	eddsa = -8
	rs256 = -257
)

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// statementChallenge: what a passkey signs for a statement - SHA-256 of its canonical text.
func statementChallenge(statement any) ([]byte, error) {
	text, err := canon.Text(statement)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(text))
	return sum[:], nil
}

// verifyAssertion checks a WebAuthn assertion: made by this passkey (SPKI,
// COSE algorithm), over this challenge, with the person present and
// verified (PIN or biometric). Origin and counter were checked by the
// server when it accepted it.
func verifyAssertion(spkiB64 string, alg int, assertion map[string]any, challenge []byte) error {
	get := func(k string) ([]byte, error) {
		s, _ := assertion[k].(string)
		return b64url(s)
	}
	clientRaw, err := get("client_data_json")
	if err != nil {
		return errors.New("bad client data")
	}
	auth, err := get("authenticator_data")
	if err != nil {
		return errors.New("bad authenticator data")
	}
	sig, err := get("signature")
	if err != nil {
		return errors.New("bad signature encoding")
	}
	var client struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if json.Unmarshal(clientRaw, &client) != nil || client.Type != "webauthn.get" {
		return errors.New("not a WebAuthn assertion")
	}
	if client.Challenge != base64.RawURLEncoding.EncodeToString(challenge) {
		return errors.New("signed another statement")
	}
	if len(auth) < 37 || auth[32]&0x05 != 0x05 {
		return errors.New("the person was not verified (PIN or biometric)")
	}
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return errors.New("bad passkey public key")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return errors.New("bad passkey public key")
	}
	clientHash := sha256.Sum256(clientRaw)
	signed := append(append([]byte{}, auth...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		ok = alg == es256 && ecdsa.VerifyASN1(k, digest[:], sig)
	case ed25519.PublicKey:
		ok = alg == eddsa && ed25519.Verify(k, signed, sig)
	case *rsa.PublicKey:
		ok = alg == rs256 && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
	default:
		return fmt.Errorf("unsupported passkey key %T", pub)
	}
	if !ok {
		return errors.New("the passkey's signature does not verify")
	}
	return nil
}

// PasskeyFingerprint: SHA256:<base64 of SHA-256 of the SPKI>, as My profile and
// tools/provenza_audit.py name a passkey.
func PasskeyFingerprint(spkiB64 string) string {
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// verifyEd25519 checks a signature over a statement's canonical text with a
// raw Ed25519 key (standard base64), as app/core/agent_signing.verify_payload.
func verifyEd25519(pubB64, sigB64 string, statement any) bool {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	text, err := canon.Text(statement)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(text), sig)
}
