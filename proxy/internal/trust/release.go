// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

// Signed policy releases (docs/pvp/edge.md, section 3.1), checked here and
// not by the server: a release is accepted only when its documents hash to
// what was signed and the quorum of the manifest that governs it - one this
// proxy already trusts - signed exactly it with passkeys that manifest lists.
// The Go counterpart of check_release in tools/provenza_audit.py.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

const releaseType = "provenza.policy.release"

// Release is a verified release: what the proxy judges by.
type Release struct {
	Number      int
	Bundle      map[string]any
	Manifest    map[string]any
	BundleSHA   string
	ManifestSHA string
	// the document as the server sent it (kept so a restart can check it again)
	Doc map[string]any
}

func num(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		return n, err == nil
	case float64:
		return int64(x), float64(int64(x)) == x
	case int:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func shaOf(v any) string {
	s, err := canon.SHA256(v)
	if err != nil {
		return ""
	}
	return s
}

// GoverningSHA: the manifest that decides who may sign this release - the
// previous release's, or for the first release its own.
func GoverningSHA(doc map[string]any) string {
	if gov := obj(doc["governed_by"]); gov != nil {
		return str(gov["manifest_sha256"])
	}
	return str(obj(obj(doc["release"])["manifest"])["sha256"])
}

// GovernedByNumber: the number of the release that governs this one (0: none).
func GovernedByNumber(doc map[string]any) int {
	n, _ := num(obj(doc["governed_by"])["number"])
	return int(n)
}

// VerifyRelease checks one release document on its own: the hashes, that it
// follows the release that governs it, and the quorum of the governing
// manifest's administrators. Returns the passkey fingerprints that signed.
func VerifyRelease(doc map[string]any) (*Release, []string, error) {
	rel, bundle, manifest := obj(doc["release"]), obj(doc["bundle"]), obj(doc["manifest"])
	if rel == nil || bundle == nil || manifest == nil {
		return nil, nil, errors.New("not a release document")
	}
	bsha, msha := str(obj(rel["bundle"])["sha256"]), str(obj(rel["manifest"])["sha256"])
	if shaOf(bundle) != bsha || shaOf(manifest) != msha || bsha == "" || msha == "" {
		return nil, nil, errors.New("a document does not hash to what the release names")
	}
	number, _ := num(rel["number"])
	bversion, _ := num(bundle["version"])
	mversion, _ := num(manifest["version"])
	governing := manifest
	if gov := obj(doc["governed_by"]); gov != nil {
		governing = obj(gov["manifest"])
		if governing == nil || shaOf(governing) != str(gov["manifest_sha256"]) {
			return nil, nil, errors.New("the governing manifest does not hash to its name")
		}
		gbv, _ := num(gov["bundle_version"])
		if str(bundle["previous"]) != str(gov["bundle_sha256"]) || bversion != gbv+1 {
			return nil, nil, errors.New("the bundle does not follow the governing release's")
		}
		gmv, _ := num(governing["version"])
		if msha != str(gov["manifest_sha256"]) && (str(manifest["previous"]) != str(gov["manifest_sha256"]) || mversion != gmv+1) {
			return nil, nil, errors.New("the manifest does not follow the governing one")
		}
	}
	orgID := bundle["org_id"]
	signed := map[string]string{}
	sigs, _ := doc["signatures"].([]any)
	for _, raw := range sigs {
		s := obj(raw)
		st := obj(s["statement"])
		if st == nil {
			continue
		}
		want := map[string]any{
			"type": releaseType, "v": json.Number("1"), "org_id": orgID, "user_id": s["user_id"],
			"release": rel["number"], "bundle": map[string]any{"version": bundle["version"], "sha256": bsha},
			"manifest":  map[string]any{"version": manifest["version"], "sha256": msha},
			"not_after": bundle["not_after"], "issued_at": st["issued_at"],
		}
		if a, b := canonText(st), canonText(want); a == "" || a != b {
			continue
		}
		uid := canonText(s["user_id"])
		person := obj(obj(governing["signers"])[uid])
		if str(person["role"]) != "admin" {
			continue
		}
		key := obj(obj(person["passkeys"])[str(s["credential_id"])])
		if key == nil {
			continue
		}
		alg, _ := num(key["alg"])
		challenge, err := statementChallenge(st)
		if err != nil || verifyAssertion(str(key["public_key"]), int(alg), obj(s["assertion"]), challenge) != nil {
			continue
		}
		signed[uid] = PasskeyFingerprint(str(key["public_key"]))
	}
	quorum, _ := num(governing["quorum"])
	if quorum < 1 {
		quorum = 1
	}
	if int64(len(signed)) < quorum {
		return nil, nil, fmt.Errorf("%d valid administrator signature(s); the governing manifest requires %d",
			len(signed), quorum)
	}
	fps := make([]string, 0, len(signed))
	for _, fp := range signed {
		fps = append(fps, fp)
	}
	return &Release{Number: int(number), Bundle: bundle, Manifest: manifest, BundleSHA: bsha, ManifestSHA: msha,
		Doc: doc}, fps, nil
}

func canonText(v any) string {
	t, err := canon.Text(v)
	if err != nil {
		return ""
	}
	return t
}

// Advance moves from the release the proxy trusts (nil: none yet) along
// releases the server sent, oldest first. A release is taken only when it is
// governed by the manifest the proxy trusts at that point - the pinned one
// (anchor: a manifest SHA-256 an administrator gave the proxy) before the
// first release is taken - and verifies. Returns the newest release taken,
// or cur when none was. tofu: with no anchor and no release yet, the first
// release's own governing manifest is trusted (trust on first use).
func Advance(cur *Release, anchor string, tofu bool, chain []map[string]any) (*Release, error) {
	trusted := anchor
	if cur != nil {
		trusted = cur.ManifestSHA
	}
	for _, doc := range chain {
		if cur != nil && GovernedByNumber(doc) != cur.Number {
			continue // not the next step from where the proxy stands
		}
		gsha := GoverningSHA(doc)
		if trusted == "" && tofu && cur == nil {
			trusted = gsha
		}
		if gsha != trusted {
			continue
		}
		r, _, err := VerifyRelease(doc)
		if err != nil {
			n, _ := num(obj(doc["release"])["number"])
			return cur, fmt.Errorf("release #%d: %w", n, err)
		}
		if cur != nil && r.Number <= cur.Number {
			continue
		}
		cur, trusted = r, r.ManifestSHA
	}
	return cur, nil
}

func parseJSON(raw []byte) (any, error) { return canon.Parse(raw) }

// ParseDocument reads a release document as the server sends it, numbers kept as text.
func ParseDocument(raw []byte) (map[string]any, error) {
	v, err := canon.Parse(raw)
	if err != nil {
		return nil, err
	}
	m := obj(v)
	if m == nil {
		return nil, errors.New("not a release document")
	}
	return m, nil
}
