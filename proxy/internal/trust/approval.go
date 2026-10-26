// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

// A human approval that releases a held call (docs/pvp/spec.md 3.1,
// docs/pvp/edge.md 3): the approver's session key signed provenza.approval
// for exactly this call, the approver's passkey certified that session key,
// and that passkey is the one the signed manifest lists for the approver.
// The Go counterpart of check_approval in tools/provenza_audit.py.

import (
	"errors"
	"fmt"
)

// Call is the action an approval must name.
type Call struct {
	AgentID     any // parsed JSON numbers (json.Number) or nil
	ChainID     any
	ActionType  string
	ToolName    string
	InputSHA256 string
}

// VerifyApproval checks an approval proof (approvals.proof_for_check on the
// server) against the signed manifest and the call. Returns the passkey
// fingerprint that certified the approver's session.
func VerifyApproval(proof map[string]any, manifest map[string]any, call Call) (string, error) {
	st, cert := obj(proof["statement"]), obj(obj(proof["certificate"])["statement"])
	if st == nil || cert == nil {
		return "", errors.New("approval: not a signed approval")
	}
	if str(st["type"]) != "provenza.approval" || str(st["decision"]) != "approved" {
		return "", errors.New("approval: not an approval")
	}
	same := func(a, b any) bool { return canonText(a) == canonText(b) }
	if !same(st["agent_id"], call.AgentID) || !same(st["chain_id"], call.ChainID) ||
		str(st["action_type"]) != call.ActionType || str(st["tool_name"]) != call.ToolName ||
		str(st["input_sha256"]) != call.InputSHA256 {
		return "", errors.New("approval: it approves another call")
	}
	sessionKey := str(proof["session_public_key"])
	if str(cert["type"]) != "provenza.session.certificate" || str(cert["public_key"]) != sessionKey {
		return "", errors.New("approval: the session certificate is not for the key that signed")
	}
	for _, k := range []string{"org_id", "user_id", "session_id"} {
		if !same(st[k], cert[k]) {
			return "", fmt.Errorf("approval: signed in another session than the certificate names (%s)", k)
		}
	}
	issued, _ := num(st["issued_at"])
	from, _ := num(cert["not_before"])
	until, _ := num(cert["not_after"])
	if issued < from || issued > until {
		return "", errors.New("approval: signed outside the session's validity")
	}
	if !verifyEd25519(sessionKey, str(proof["signature"]), st) {
		return "", errors.New("approval: the session key's signature does not verify")
	}
	person := obj(obj(manifest["signers"])[canonText(st["user_id"])])
	certificate := obj(proof["certificate"])
	key := obj(obj(person["passkeys"])[str(certificate["credential_id"])])
	if key == nil || str(key["public_key"]) != str(obj(proof["passkey"])["public_key"]) {
		return "", errors.New("approval: the approver's passkey is not in the signed manifest")
	}
	alg, _ := smallInt(key["alg"])
	challenge, err := statementChallenge(cert)
	if err != nil {
		return "", err
	}
	if err := verifyAssertion(str(key["public_key"]), alg, obj(certificate["assertion"]), challenge); err != nil {
		return "", fmt.Errorf("approval: the passkey did not certify the session: %w", err)
	}
	return PasskeyFingerprint(str(key["public_key"])), nil
}
