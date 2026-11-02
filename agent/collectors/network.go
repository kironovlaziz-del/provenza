package collectors

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"shadow-ai-agent/config"
	"shadow-ai-agent/reporters"
)

// KnownAIPorts maps known listening ports to default software names and risk scores.
var KnownAIPorts = map[int]struct {
	Name string
	Risk float64
}{
	11434: {Name: "Ollama API", Risk: 0.6},
	1234:  {Name: "LM Studio API", Risk: 0.7},
	8080:  {Name: "LocalAI / llama.cpp HTTP", Risk: 0.6},
	8000:  {Name: "vLLM Server", Risk: 0.7},
	5000:  {Name: "LocalAI / WebUI", Risk: 0.5},
	3000:  {Name: "Open-WebUI", Risk: 0.5},
}

// NetworkCollector checks for local listening AI endpoints.
type NetworkCollector struct {
	cfg       *config.AgentConfig
	reporter  *reporters.Reporter
	openPorts map[int]bool
	mu        sync.Mutex
}

// NewNetworkCollector creates an instance of the network port scanner.
func NewNetworkCollector(cfg *config.AgentConfig, rep *reporters.Reporter) *NetworkCollector {
	return &NetworkCollector{
		cfg:       cfg,
		reporter:  rep,
		openPorts: make(map[int]bool),
	}
}

// ScanOnce tests local TCP port listeners.
func (c *NetworkCollector) ScanOnce() {
	who := currentUser()

	for port, meta := range KnownAIPorts {
		target := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.DialTimeout("tcp", target, 500*time.Millisecond)

		isOpen := (err == nil)
		if isOpen {
			_ = conn.Close()
		}

		c.mu.Lock()
		wasOpen := c.openPorts[port]
		c.openPorts[port] = isOpen
		c.mu.Unlock()

		if isOpen && !wasOpen {
			log.Printf("[NetworkCollector] Detected active AI service on local port %d (%s)", port, meta.Name)
			c.reporter.Submit(reporters.TelemetryEvent{
				EventType:   "network_conn",
				AgentID:     c.cfg.AgentID,
				Domain:      fmt.Sprintf("localhost:%d", port),
				UserID:      who,
				RiskScore:   meta.Risk,
				ActionTaken: "monitored",
				Payload: map[string]interface{}{
					"port":        port,
					"target_host": "127.0.0.1",
					"service":     meta.Name,
				},
			})
		}
	}
}

// RunPeriodic runs the port monitor loop.
func (c *NetworkCollector) RunPeriodic(stopChan <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(c.cfg.ScanIntervalSec*2) * time.Second)
	defer ticker.Stop()

	c.ScanOnce()
	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			c.ScanOnce()
		}
	}
}
