// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

// Who sealed a credential (docs/pvp/edge.md, section 4.1): the administrator
// who sealed it in the browser signed, with their session key, the object,
// the origin and the SHA-256 of each proxy's envelope
// (provenza.credential.sealed, backend/app/services/credentials.py); their
// passkey certified that session key, and that passkey belongs to an
// administrator in the signed manifest. The server, which only carries the
// envelopes, cannot vouch for one of its own.

import (
	"errors"
	"fmt"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

const sealedType = "provenza.credential.sealed"

// SealedWant is what a sealer's statement must name.
type SealedWant struct {
	OrgID          any // parsed JSON numbers (json.Number) or Go numbers
	Object         string
	ObjectID       any
	ProxyID        any
	Upstream       string
	EnvelopeSHA256 string
}

// VerifySealed checks the sealer's proof of one envelope against the signed
// manifest. Returns the administrator's user id.
func VerifySealed(proof map[string]any, manifest map[string]any, want SealedWant) (string, error) {
	st, cert := obj(proof["statement"]), obj(obj(proof["certificate"])["statement"])
	if st == nil || cert == nil {
		return "", errors.New("sealer: not signed")
	}
	if str(st["type"]) != sealedType {
		return "", errors.New("sealer: not a sealing statement")
	}
	if v, _ := num(st["v"]); v != 1 {
		return "", errors.New("sealer: unknown statement version")
	}
	same := func(a, b any) bool { return asText(a) == asText(b) && asText(a) != "" }
	if !same(st["org_id"], want.OrgID) || !same(st["org_id"], manifest["org_id"]) || str(st["object"]) != want.Object ||
		!same(st["object_id"], want.ObjectID) || str(st["upstream"]) != want.Upstream {
		return "", errors.New("sealer: it vouches for another object or origin")
	}
	if str(obj(st["envelopes"])[asText(want.ProxyID)]) != want.EnvelopeSHA256 || want.EnvelopeSHA256 == "" {
		return "", errors.New("sealer: it vouches for another envelope")
	}
	sessionKey := str(proof["session_public_key"])
	if str(cert["type"]) != "provenza.session.certificate" || str(cert["public_key"]) != sessionKey {
		return "", errors.New("sealer: the session certificate is not for the key that signed")
	}
	for _, k := range []string{"org_id", "user_id", "session_id"} {
		if !same(st[k], cert[k]) {
			return "", fmt.Errorf("sealer: signed in another session than the certificate names (%s)", k)
		}
	}
	issued, _ := num(st["issued_at"])
	from, _ := num(cert["not_before"])
	until, _ := num(cert["not_after"])
	if issued < from || issued > until {
		return "", errors.New("sealer: signed outside the session's validity")
	}
	if !verifyEd25519(sessionKey, str(proof["signature"]), st) {
		return "", errors.New("sealer: the session key's signature does not verify")
	}
	user := canonText(st["user_id"])
	person := obj(obj(manifest["signers"])[user])
	if str(person["role"]) != "admin" {
		return "", errors.New("sealer: not an administrator in the signed manifest")
	}
	certificate := obj(proof["certificate"])
	key := obj(obj(person["passkeys"])[str(certificate["credential_id"])])
	if key == nil || str(key["public_key"]) != str(obj(proof["passkey"])["public_key"]) {
		return "", errors.New("sealer: the passkey is not in the signed manifest")
	}
	alg, _ := num(key["alg"])
	challenge, err := statementChallenge(cert)
	if err != nil {
		return "", err
	}
	if err := verifyAssertion(str(key["public_key"]), int(alg), obj(certificate["assertion"]), challenge); err != nil {
		return "", fmt.Errorf("sealer: the passkey did not certify the session: %w", err)
	}
	return user, nil
}

// asText: the canonical text of a value - parsed JSON or a Go value (an int64 id).
func asText(v any) string {
	p, err := canon.Of(v)
	if err != nil {
		return ""
	}
	return canonText(p)
}
