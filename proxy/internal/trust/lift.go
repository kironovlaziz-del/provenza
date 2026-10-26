// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

// Lifting a local kill switch (docs/pvp/edge.md, section 7): administrators
// sign, each with a passkey, that they saw the reconciliation report the
// enforcement point made - by its hash - and accept the differences no
// signed release explains. Only the manifest the enforcement point held
// before the outage counts, so a passkey the server slipped in meanwhile
// cannot lift anything.

import (
	"errors"
	"fmt"
)

const liftType = "provenza.kill_switch.lift"

// LiftWant is what a lift signature must name.
type LiftWant struct {
	ProxyID      string   // the enforcement point, as the server numbers it
	ReportSHA256 string   // the report the enforcement point made
	Unsigned     []string // the differences no signed release explains: each must be accepted
	NotBefore    int64    // when the kill switch engaged: an older signature lifts nothing
	Now          int64    // this host's clock: an expired signature lifts nothing
}

// maxLiftLife: the longest a lift signature may be valid (Provenza makes them valid for 12 hours).
const maxLiftLife = 24 * 3600

// VerifyLift: the administrators of the manifest (the one held before the
// outage) whose passkey signed this lift. Signatures that do not verify are
// skipped, with the reasons.
func VerifyLift(signatures []any, manifest map[string]any, want LiftWant) ([]string, []string) {
	var users, problems []string
	seen := map[string]bool{}
	for i, s := range signatures {
		user, err := verifyLift(obj(s), manifest, want)
		if err != nil {
			problems = append(problems, fmt.Sprintf("signature %d: %v", i+1, err))
			continue
		}
		if !seen[user] {
			seen[user] = true
			users = append(users, user)
		}
	}
	return users, problems
}

// Quorum of a manifest (at least 1).
func Quorum(manifest map[string]any) int {
	n, ok := smallInt(manifest["quorum"])
	if !ok || n < 1 {
		return 1
	}
	return n
}

func verifyLift(sig, manifest map[string]any, want LiftWant) (string, error) {
	st := obj(sig["statement"])
	if st == nil || str(st["type"]) != liftType {
		return "", errors.New("not a lift")
	}
	if v, _ := num(st["v"]); v != 1 {
		return "", errors.New("unknown statement version")
	}
	if canonText(st["org_id"]) != canonText(manifest["org_id"]) {
		return "", errors.New("another organization")
	}
	if canonText(st["proxy_id"]) != want.ProxyID || str(st["report_sha256"]) != want.ReportSHA256 {
		return "", errors.New("it lifts another report")
	}
	issued, ok := num(st["issued_at"])
	if !ok || issued < want.NotBefore {
		return "", errors.New("signed before the kill switch engaged")
	}
	expires, ok := num(st["expires_at"])
	if !ok || expires-issued > maxLiftLife || expires < issued {
		return "", errors.New("the signature's validity is missing or too long")
	}
	if want.Now > expires {
		return "", errors.New("the signature has expired")
	}
	accepted := map[string]bool{}
	list, _ := st["accept"].([]any)
	for _, a := range list {
		accepted[str(a)] = true
	}
	for _, id := range want.Unsigned {
		if !accepted[id] {
			return "", fmt.Errorf("does not accept %s", id)
		}
	}
	user := canonText(st["user_id"])
	if user != canonText(sig["user_id"]) {
		return "", errors.New("signed by someone else than it says")
	}
	person := obj(obj(manifest["signers"])[user])
	if str(person["role"]) != "admin" {
		return "", errors.New("the signer is not an administrator in the manifest before the outage")
	}
	key := obj(obj(person["passkeys"])[str(sig["credential_id"])])
	if key == nil {
		return "", errors.New("the passkey is not in the manifest before the outage")
	}
	alg, _ := smallInt(key["alg"])
	challenge, err := statementChallenge(st)
	if err != nil {
		return "", err
	}
	if err := verifyAssertion(str(key["public_key"]), alg, obj(sig["assertion"]), challenge); err != nil {
		return "", fmt.Errorf("the passkey's signature: %w", err)
	}
	return user, nil
}
