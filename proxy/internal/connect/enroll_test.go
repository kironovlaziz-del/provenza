// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package connect

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// fakeEnrollment: the server's side (services/enrollment.py) - it checks the
// proof over exactly the statement, both halves for a hybrid key.
func fakeEnrollment(t *testing.T, requireHybrid bool, purpose string, templateName string) (*httptest.Server, *map[string]any) {
	t.Helper()
	got := map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/api/v1/agent-enrollment/challenge":
			if in["token"] != "pvz_enr_good" {
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(map[string]any{"detail": "enrollment.invalid_token"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"enrollment_id": 4, "org_id": 2, "purpose": purpose,
				"challenge": "ab", "name": templateName, "require_hybrid": requireHybrid})
		case "/api/v1/agent-enrollment/enroll":
			got = in
			var pq any
			if in["pq_public_key"] != nil {
				pq = in["pq_public_key"]
			}
			st := map[string]any{"type": "provenza.agent.enroll", "v": 1, "challenge": "ab", "org_id": 2,
				"enrollment_id": 4, "public_key": in["public_key"], "pq_public_key": pq, "name": in["name"]}
			msg, _ := canon.Bytes(st)
			pub, _ := base64.StdEncoding.DecodeString(in["public_key"].(string))
			sig, _ := base64.StdEncoding.DecodeString(in["signature"].(string))
			ok := ed25519.Verify(pub, msg, sig)
			if pq != nil {
				raw, _ := base64.StdEncoding.DecodeString(pq.(string))
				k, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
				ps, _ := base64.StdEncoding.DecodeString(in["pq_signature"].(string))
				ok = ok && err == nil && mldsa.Verify(k, msg, ps, nil) == nil
			}
			if !ok {
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(map[string]any{"detail": "enrollment.bad_proof"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"agent_id": 31, "name": in["name"], "api_key": "api-31",
				"key_fingerprint": "SHA256:x", "purpose": purpose})
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestEnrollMakesTheKeysHere(t *testing.T) {
	for _, hybrid := range []bool{false, true} {
		srv, got := fakeEnrollment(t, hybrid, "new", "")
		path := filepath.Join(t.TempDir(), "provenza", "provenza-agent.json")
		os.MkdirAll(filepath.Dir(path), 0o700)
		os.WriteFile(path, []byte("{}"), 0o600) // an older identity is kept aside
		id, purpose, err := Enroll(EnrollOptions{Server: srv.URL, Token: "pvz_enr_good", Name: "gemini@box", Path: path})
		if err != nil || purpose != "new" || id.AgentID != 31 || id.APIKey != "api-31" {
			t.Fatalf("hybrid=%v: %v %+v", hybrid, err, id)
		}
		if (id.PQPrivateKey != "") != hybrid || (*got)["name"] != "gemini@box" {
			t.Fatalf("hybrid=%v: %+v %v", hybrid, id, *got)
		}
		if _, sent := (*got)["private_key"]; sent {
			t.Fatal("the private key was sent")
		}
		st, _ := os.Stat(path)
		var saved Identity
		raw, _ := os.ReadFile(path)
		json.Unmarshal(raw, &saved)
		if st.Mode().Perm() != 0o600 || saved.PrivateKey != id.PrivateKey || saved.Server != srv.URL {
			t.Fatalf("identity file: %v %+v", st.Mode(), saved)
		}
		if old, _ := filepath.Glob(path + ".*.old"); len(old) != 1 {
			t.Fatalf("the older identity was not kept: %v", old)
		}
	}
}

func TestEnrollRefusals(t *testing.T) {
	srv, _ := fakeEnrollment(t, false, "new", "")
	path := filepath.Join(t.TempDir(), "id.json")
	if _, _, err := Enroll(EnrollOptions{Server: srv.URL, Token: "pvz_enr_bad", Name: "x", Path: path}); err == nil {
		t.Fatal("a bad token was accepted")
	}
	if _, _, err := Enroll(EnrollOptions{Server: "http://provenza.example.com", Token: "pvz_enr_good", Path: path}); err == nil {
		t.Fatal("plain http to a remote server")
	}
	if _, _, err := Enroll(EnrollOptions{Server: srv.URL, Token: "pvz_enr_good", Path: path}); err == nil {
		t.Fatal("a new agent without a name")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("an identity was written for a refused enrollment")
	}
	// a re-key keeps the agent's name: nothing is sent for it
	srv2, got := fakeEnrollment(t, false, "rekey", "")
	if _, purpose, err := Enroll(EnrollOptions{Server: srv2.URL, Token: "pvz_enr_good", Name: "x", Path: path}); err != nil || purpose != "rekey" || (*got)["name"] != "" {
		t.Fatalf("rekey: %v %v", err, *got)
	}
}
