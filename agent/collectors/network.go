package collectors

import (
	"fmt"
	"log"
	"net"
	"strings"
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

// NetworkCollector checks for local listening AI endpoints: an open port, and
// then what answers there (probeModelAPI). A port where no model API answers
// is still reported, with "confirmed": false and a low risk.
type NetworkCollector struct {
	cfg       *config.AgentConfig
	reporter  *reporters.Reporter
	openPorts map[int]string // port -> what was reported for it ("" closed)
	mu        sync.Mutex
	probe     func(base string, port int) modelAPIResult
}

// unconfirmedRisk: an open model port where no model API answers - most likely
// a developer's own web server.
const unconfirmedRisk = 0.2

// NewNetworkCollector creates an instance of the network port scanner.
func NewNetworkCollector(cfg *config.AgentConfig, rep *reporters.Reporter) *NetworkCollector {
	return &NetworkCollector{
		cfg:       cfg,
		reporter:  rep,
		openPorts: make(map[int]string),
		probe:     probeModelAPI,
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

		if !isOpen {
			c.mu.Lock()
			c.openPorts[port] = ""
			c.mu.Unlock()
			continue
		}

		res := c.probe(fmt.Sprintf("http://127.0.0.1:%d", port), port)
		if !c.changed(port, res) {
			continue // reported already, nothing changed
		}
		if res.Confirmed {
			log.Printf("[NetworkCollector] %s answers on local port %d (%d models)", res.API, port, len(res.Models))
		} else {
			log.Printf("[NetworkCollector] Port %d is open, no model API answers there", port)
		}
		ev := portEvent(port, meta.Name, meta.Risk, res)
		ev.AgentID, ev.UserID = c.cfg.AgentID, who
		c.reporter.Submit(ev)
	}
}

// changed: what answers on the port is not what was reported last.
func (c *NetworkCollector) changed(port int, res modelAPIResult) bool {
	state := fmt.Sprintf("open|%v|%s|%s", res.Confirmed, res.API, strings.Join(res.Models, ","))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.openPorts[port] == state {
		return false
	}
	c.openPorts[port] = state
	return true
}

// portEvent: the report of a model port: confirmed, with its API and models; or not.
func portEvent(port int, name string, risk float64, res modelAPIResult) reporters.TelemetryEvent {
	service := name
	if !res.Confirmed {
		service, risk = fmt.Sprintf("a service on port %d (no model API answered)", port), unconfirmedRisk
	}
	payload := map[string]interface{}{
		"port":        port,
		"target_host": "127.0.0.1",
		"service":     service,
		"confirmed":   res.Confirmed,
	}
	if res.Confirmed {
		payload["api"] = res.API
		payload["models"] = res.Models
	}
	return reporters.TelemetryEvent{
		EventType:   "network_conn",
		Domain:      fmt.Sprintf("localhost:%d", port),
		RiskScore:   risk,
		ActionTaken: "monitored",
		Payload:     payload,
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
