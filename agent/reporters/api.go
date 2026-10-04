package reporters

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

// Reporter buffers and delivers telemetry events to the central collector API.
type Reporter struct {
	cfg        *config.AgentConfig
	eventChan  chan TelemetryEvent
	httpClient *http.Client
	mu         sync.Mutex
	buffer     []TelemetryEvent
	done       chan struct{}
}

// NewReporter initializes the HTTP client and worker buffer.
func NewReporter(cfg *config.AgentConfig) *Reporter {
	return &Reporter{
		cfg:       cfg,
		eventChan: make(chan TelemetryEvent, 1000),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		buffer: make([]TelemetryEvent, 0, cfg.BatchSize),
		done:   make(chan struct{}),
	}
}

// AgentVersion identifies this build to the backend (shown on Devices).
const AgentVersion = "1.2.0"

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
	ticker := time.NewTicker(time.Duration(r.cfg.BatchIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.done:
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

// Stop initiates graceful flush and shuts down the reporter.
func (r *Reporter) Stop() {
	close(r.done)
}

func (r *Reporter) flush() {
	r.mu.Lock()
	if len(r.buffer) == 0 {
		r.mu.Unlock()
		return
	}
	eventsToSend := make([]TelemetryEvent, len(r.buffer))
	copy(eventsToSend, r.buffer)
	r.buffer = r.buffer[:0]
	r.mu.Unlock()

	payload := TelemetryBatch{Events: eventsToSend}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Reporter] JSON marshal error: %v", err)
		return
	}

	req, err := http.NewRequest("POST", r.cfg.APIURL, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[Reporter] Failed to create HTTP request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ingestion-Key", r.cfg.IngestionKey)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("[Reporter] Network error transmitting batch of %d events: %v", len(eventsToSend), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[Reporter] Successfully pushed %d events (HTTP %d)", len(eventsToSend), resp.StatusCode)
	} else {
		log.Printf("[Reporter] Ingest rejected batch with HTTP status: %d", resp.StatusCode)
	}
}
