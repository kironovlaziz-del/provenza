package reporters

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"shadow-ai-agent/config"
)

// TelemetryEvent matches the backend TelemetryEventIn schema.
type TelemetryEvent struct {
	EventID     string                 `json:"event_id"`
	EventType   string                 `json:"event_type"`
	AgentID     string                 `json:"agent_id"`
	Domain      string                 `json:"domain,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	RiskScore   float64                `json:"risk_score"`
	ActionTaken string                 `json:"action_taken"`
	Payload     map[string]interface{} `json:"payload"`
	Timestamp   string                 `json:"timestamp"`
}

// TelemetryBatch matches the backend TelemetryBatchIn schema.
type TelemetryBatch struct {
	Events []TelemetryEvent `json:"events"`
}

// GenerateUUID generates a mock UUIDv4 string.
func GenerateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Reporter buffers and delivers telemetry events to the central collector
// API. A batch the server does not accept (no network, server down,
// overloaded) goes to the on-disk queue and is sent again later, oldest
// first; only a batch the server rejects as malformed is dropped.
type Reporter struct {
	cfg        *config.AgentConfig
	eventChan  chan TelemetryEvent
	httpClient *http.Client
	mu         sync.Mutex
	buffer     []TelemetryEvent
	done       chan struct{}
	finished   chan struct{}
	queue      *diskQueue // nil: no usable state directory, failures are dropped
	retryAt    time.Time  // after a failure, the queue waits until then
	backoff    time.Duration
}

// NewReporter initializes the HTTP client, the worker buffer and the
// on-disk queue.
func NewReporter(cfg *config.AgentConfig) *Reporter {
	r := &Reporter{
		cfg:       cfg,
		eventChan: make(chan TelemetryEvent, 1000),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		buffer:   make([]TelemetryEvent, 0, cfg.BatchSize),
		done:     make(chan struct{}),
		finished: make(chan struct{}),
	}
	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = config.DefaultStateDir()
	}
	q, err := openQueue(stateDir, cfg.QueueMaxMB)
	if err != nil {
		log.Printf("[Reporter] No on-disk queue (%v): events are lost while the server is unreachable", err)
	} else {
		r.queue = q
		if n := q.len(); n > 0 {
			log.Printf("[Reporter] %d undelivered batch(es) in %s, sending them first", n, q.dir)
		}
	}
	return r
}

// AgentVersion identifies this build to the backend (shown on Devices).
// Set at build time with -ldflags "-X shadow-ai-agent/reporters.AgentVersion=...".
var AgentVersion = "1.5.0"

// Submit puts an event into the delivery channel. It returns false when the
// buffer is full and the event was dropped.
func (r *Reporter) Submit(event TelemetryEvent) bool {
	if event.Payload == nil {
		event.Payload = map[string]interface{}{}
	}
	// Device facts for the backend's device registry.
	event.Payload["os"] = runtime.GOOS
	event.Payload["agent_version"] = AgentVersion
	if event.EventID == "" {
		event.EventID = GenerateUUID()
	}
	if event.AgentID == "" {
		event.AgentID = r.cfg.AgentID
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	select {
	case r.eventChan <- event:
		return true
	default:
		log.Printf("[Reporter] Event buffer full, dropping event: %s", event.EventType)
		return false
	}
}

// Start runs the periodic flush worker in the background.
func (r *Reporter) Start() {
	defer close(r.finished)
	ticker := time.NewTicker(time.Duration(r.cfg.BatchIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.done:
			// take what is still in the channel, then one last attempt;
			// whatever is not delivered stays in the queue for next start
		drain:
			for {
				select {
				case event := <-r.eventChan:
					r.mu.Lock()
					r.buffer = append(r.buffer, event)
					r.mu.Unlock()
				default:
					break drain
				}
			}
			r.retryAt = time.Time{}
			r.flush()
			return
		case event := <-r.eventChan:
			r.mu.Lock()
			r.buffer = append(r.buffer, event)
			needFlush := len(r.buffer) >= r.cfg.BatchSize
			r.mu.Unlock()

			if needFlush {
				r.flush()
			}
		case <-ticker.C:
			r.flush()
		}
	}
}

// Stop flushes what is buffered and waits (at most 20 s) for the worker.
func (r *Reporter) Stop() {
	close(r.done)
	select {
	case <-r.finished:
	case <-time.After(20 * time.Second):
		log.Printf("[Reporter] Shutdown timed out; unsent events may be lost")
	}
}

// sendResult is how the server answered one batch.
type sendResult int

const (
	sent      sendResult = iota
	retry                // network error, 5xx, 429, 408, 401/403: keep it
	malformed            // any other 4xx: sending it again cannot succeed
)

func (r *Reporter) flush() {
	r.mu.Lock()
	var data []byte
	n := len(r.buffer)
	if n > 0 {
		var err error
		data, err = json.Marshal(TelemetryBatch{Events: r.buffer})
		r.buffer = r.buffer[:0]
		if err != nil {
			r.mu.Unlock()
			log.Printf("[Reporter] JSON marshal error: %v", err)
			return
		}
	}
	r.mu.Unlock()

	if r.queue == nil {
		if data != nil && r.send(data, n) != sent {
			log.Printf("[Reporter] %d event(s) lost (no on-disk queue)", n)
		}
		return
	}

	// with a queue, order matters: a new batch goes behind the waiting ones
	if data != nil {
		if r.queue.len() == 0 && !r.waiting() {
			switch r.send(data, n) {
			case sent:
				r.recovered()
				return
			case malformed:
				return
			}
			r.enqueue(data, n)
			r.failed()
			return
		}
		r.enqueue(data, n)
	}
	r.drain()
}

// drain sends queued batches, oldest first, until one fails.
func (r *Reporter) drain() {
	for !r.waiting() {
		name, data, ok := r.queue.oldest()
		if !ok {
			return
		}
		switch r.send(data, -1) {
		case sent, malformed:
			r.queue.remove(name)
			r.recovered()
		default:
			r.failed()
			return
		}
	}
}

func (r *Reporter) enqueue(data []byte, n int) {
	if err := r.queue.push(data); err != nil {
		log.Printf("[Reporter] Cannot queue %d event(s): %v", n, err)
	}
}

func (r *Reporter) waiting() bool { return time.Now().Before(r.retryAt) }

// failed: wait before the next attempt, 10 s doubling up to 5 minutes.
func (r *Reporter) failed() {
	if r.backoff == 0 {
		r.backoff = 10 * time.Second
	} else if r.backoff < 5*time.Minute {
		r.backoff *= 2
		if r.backoff > 5*time.Minute {
			r.backoff = 5 * time.Minute
		}
	}
	r.retryAt = time.Now().Add(r.backoff)
	if r.queue != nil {
		log.Printf("[Reporter] Server unreachable: %d batch(es) queued, next attempt in %s", r.queue.len(), r.backoff)
	}
}

func (r *Reporter) recovered() {
	r.backoff = 0
	r.retryAt = time.Time{}
}

// send posts one batch. n is its event count for the log (-1: queued).
func (r *Reporter) send(data []byte, n int) sendResult {
	what := fmt.Sprintf("%d events", n)
	if n < 0 {
		what = "a queued batch"
	}
	req, err := http.NewRequest("POST", r.cfg.APIURL, bytes.NewReader(data))
	if err != nil {
		log.Printf("[Reporter] Failed to create HTTP request: %v", err)
		return malformed
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ingestion-Key", r.cfg.IngestionKey)
	req.Header.Set("User-Agent", "provenza-agent/"+AgentVersion+" ("+runtime.GOOS+")")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("[Reporter] Network error transmitting %s: %v", what, err)
		return retry
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		log.Printf("[Reporter] Successfully pushed %s (HTTP %d)", what, code)
		return sent
	case code >= 500, code == 429, code == 408, code == 401, code == 403:
		log.Printf("[Reporter] Server did not accept %s (HTTP %d); it will be sent again", what, code)
		return retry
	default:
		log.Printf("[Reporter] Ingest rejected %s with HTTP status %d; dropped", what, code)
		return malformed
	}
}

func droppedLog(name string) {
	log.Printf("[Reporter] Queue full: dropped the oldest batch %s", name)
}
