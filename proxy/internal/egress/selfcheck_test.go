package egress

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// The egress self-check as the SDKs run it: the targets tried directly, the
// beacon, a report signed over what the server rebuilds (egress_check.signed_payload).
func TestSelfcheckReportsWhatTheHostReached(t *testing.T) {
	ev := enforceVectors(t)
	id, err := LoadAgentIdentity(identityFile(t, agentFields(ev), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0") // a target this host reaches
	defer ln.Close()
	var report map[string]any
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/egress-check", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Key") != id.APIKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"check_id": 7,
			"targets": []string{ln.Addr().String(), "127.0.0.1:1"}, "beacon_url": srv.URL + "/egress-beacon/tok"})
	})
	mux.HandleFunc("/egress-beacon/tok", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/api/v1/agents/egress-check/7/report", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&report)
		_ = json.NewEncoder(w).Encode(map[string]any{"verdict": "open"})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	id.Server = srv.URL

	verdict, err := id.Selfcheck(context.Background(), SelfcheckAPIs(id, "http://127.0.0.1:1"), time.Second, nil)
	if err != nil || verdict != "open" {
		t.Fatalf("verdict %q, %v", verdict, err)
	}
	if report["beacon_reached"] != true {
		t.Fatalf("the beacon was reached: %v", report)
	}
	results := []any{map[string]any{"target": "127.0.0.1:1", "reachable": false},
		map[string]any{"target": ln.Addr().String(), "reachable": true}}
	if ln.Addr().String() < "127.0.0.1:1" {
		results[0], results[1] = results[1], results[0]
	}
	msg, _ := canon.Bytes(map[string]any{"type": "egress.report", "agent_id": id.AgentID, "check_id": int64(7),
		"results": results, "beacon_reached": true})
	sig, _ := base64.StdEncoding.DecodeString(report["signature"].(string))
	pub, _ := base64.StdEncoding.DecodeString(id.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatalf("the report is not signed over %s", msg)
	}
	if id.Hybrid() && report["pq_signature"] == nil {
		t.Fatal("a hybrid key signs both halves")
	}
}

// Only an unreachable address moves on to the next (the relay of a local
// egress proxy); Provenza's refusal is final.
func TestARefusalIsFinalAnUnreachableAddressIsNot(t *testing.T) {
	ev := enforceVectors(t)
	id, err := LoadAgentIdentity(identityFile(t, agentFields(ev), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	_, err = id.Selfcheck(context.Background(), []string{"http://127.0.0.1:1/api/v1", srv.URL + "/_provenza/api/v1"},
		time.Second, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "Provenza refused (HTTP 403)") {
		t.Fatalf("got %v", err)
	}
	id.Server = "https://provenza.example.com/"
	if got := SelfcheckAPIs(id, "http://127.0.0.1:8443"); len(got) != 2 ||
		got[0] != "https://provenza.example.com/api/v1" || got[1] != "http://127.0.0.1:8443/_provenza/api/v1" {
		t.Fatal(got)
	}
	// the agent's key does not travel in the clear to another machine
	if got := SelfcheckAPIs(id, "http://provenza-proxy:8443"); len(got) != 1 {
		t.Fatal(got)
	}
	// agent mode's upstream is the server's own gateways: no relay to try
	if got := SelfcheckAPIs(id, "https://provenza.example.com/api/v1"); len(got) != 1 {
		t.Fatal(got)
	}
}
