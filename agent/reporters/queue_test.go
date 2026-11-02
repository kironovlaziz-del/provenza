package reporters

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"shadow-ai-agent/config"
)

// ingest is a fake server: status decides the answer, received keeps
// the event types it accepted, in order.
type ingest struct {
	mu       sync.Mutex
	status   int
	received []string
}

func (g *ingest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.status != http.StatusOK {
		w.WriteHeader(g.status)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var b TelemetryBatch
	_ = json.Unmarshal(body, &b)
	for _, e := range b.Events {
		g.received = append(g.received, e.EventType)
	}
	w.WriteHeader(http.StatusOK)
}

func (g *ingest) set(status int) { g.mu.Lock(); g.status = status; g.mu.Unlock() }

func newTestReporter(t *testing.T, url, state string) *Reporter {
	t.Helper()
	return NewReporter(&config.AgentConfig{APIURL: url, IngestionKey: "k", BatchSize: 50,
		BatchIntervalSec: 3600, StateDir: state, QueueMaxMB: 1})
}

func onDisk(t *testing.T, state string) int {
	m, _ := filepath.Glob(filepath.Join(state, "queue", "*"+queueSuffix))
	return len(m)
}

func TestQueueSurvivesOutageAndRestart(t *testing.T) {
	g := &ingest{status: http.StatusServiceUnavailable}
	srv := httptest.NewServer(g)
	defer srv.Close()
	state := t.TempDir()

	r := newTestReporter(t, srv.URL, state)
	r.Submit(TelemetryEvent{EventType: "first"})
	r.buffer = append(r.buffer, <-r.eventChan)
	r.flush() // 503: queued
	r.Submit(TelemetryEvent{EventType: "second"})
	r.buffer = append(r.buffer, <-r.eventChan)
	r.flush() // waiting (backoff): queued behind the first
	if n := onDisk(t, state); n != 2 {
		t.Fatalf("queued %d, want 2", n)
	}

	// the agent restarts; the server is back
	g.set(http.StatusOK)
	r2 := newTestReporter(t, srv.URL, state)
	r2.Submit(TelemetryEvent{EventType: "third"})
	r2.buffer = append(r2.buffer, <-r2.eventChan)
	r2.flush()
	if n := onDisk(t, state); n != 0 {
		t.Fatalf("queue not drained: %d left", n)
	}
	if want := []string{"first", "second", "third"}; len(g.received) != 3 ||
		g.received[0] != want[0] || g.received[1] != want[1] || g.received[2] != want[2] {
		t.Fatalf("received %v, want %v (oldest first)", g.received, want)
	}
}

func TestNetworkErrorIsQueuedMalformedIsDropped(t *testing.T) {
	state := t.TempDir()
	r := newTestReporter(t, "http://127.0.0.1:1/ingest", state) // nothing listens
	r.buffer = append(r.buffer, TelemetryEvent{EventType: "x"})
	r.flush()
	if n := onDisk(t, state); n != 1 {
		t.Fatalf("network error: queued %d, want 1", n)
	}

	g := &ingest{status: http.StatusUnprocessableEntity}
	srv := httptest.NewServer(g)
	defer srv.Close()
	r2 := newTestReporter(t, srv.URL, state)
	r2.flush()
	if n := onDisk(t, state); n != 0 {
		t.Fatalf("422 must drop the batch, %d left", n)
	}
}

func TestQueueBoundedBySize(t *testing.T) {
	q, err := openQueue(t.TempDir(), 1) // 1 MB
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 300<<10)
	for i := 0; i < 6; i++ {
		if err := q.push(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if n := q.len(); n != 3 {
		t.Fatalf("%d batches kept, want 3 (the newest within 1 MB)", n)
	}
}

func TestNoStateDirStillSends(t *testing.T) {
	g := &ingest{status: http.StatusOK}
	srv := httptest.NewServer(g)
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	r := newTestReporter(t, srv.URL, file) // a file, not a directory: no queue
	if r.queue != nil {
		t.Fatal("queue opened under a file")
	}
	r.buffer = append(r.buffer, TelemetryEvent{EventType: "x"})
	r.flush()
	if len(g.received) != 1 {
		t.Fatal("not sent without a queue")
	}
}

func TestStopFlushes(t *testing.T) {
	g := &ingest{status: http.StatusOK}
	srv := httptest.NewServer(g)
	defer srv.Close()
	r := newTestReporter(t, srv.URL, t.TempDir())
	go r.Start()
	r.Submit(TelemetryEvent{EventType: "last"})
	r.Stop()
	if len(g.received) != 1 || g.received[0] != "last" {
		t.Fatalf("received %v", g.received)
	}
}
