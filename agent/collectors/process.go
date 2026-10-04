package collectors

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"shadow-ai-agent/config"
	"shadow-ai-agent/reporters"
)

// agentHeartbeat is how often a product that is still running is reported
// again, so the backend's "last seen" stays current without an event per scan.
const agentHeartbeat = time.Hour

// ProcessCollector inspects running processes on the host.
type ProcessCollector struct {
	cfg        *config.AgentConfig
	reporter   *reporters.Reporter
	seenPIDs   map[int]string
	agentsSent map[string]time.Time // product -> last report
	userNames  map[string]string    // uid -> user name
	mu         sync.Mutex
}

// NewProcessCollector creates an instance of the process monitor.
func NewProcessCollector(cfg *config.AgentConfig, rep *reporters.Reporter) *ProcessCollector {
	return &ProcessCollector{
		cfg:        cfg,
		reporter:   rep,
		seenPIDs:   make(map[int]string),
		agentsSent: make(map[string]time.Time),
		userNames:  make(map[string]string),
	}
}

// ScanOnce reads /proc on Linux systems to detect active local AI runtimes.
func (c *ProcessCollector) ScanOnce() {
	procDir, err := os.Open("/proc")
	if err != nil {
		return // Not running on Linux or /proc is inaccessible
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return
	}

	activePIDs := make(map[int]bool)
	agentsNow := make(map[string]agentHit)

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}
		activePIDs[pid] = true

		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		commName := strings.TrimSpace(string(commBytes))

		cmdlineBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		argv := strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00")

		for _, m := range MatchProcess(commName, argv) {
			if m.Signature.Kind == "agent" {
				if _, seen := agentsNow[m.Signature.Product]; !seen {
					agentsNow[m.Signature.Product] = agentHit{comm: commName, pid: pid, by: m.By, risk: m.Signature.Risk,
						user: c.processUser(pid)}
				}
				continue
			}
			c.mu.Lock()
			alreadyReported := c.seenPIDs[pid] == commName
			if !alreadyReported {
				c.seenPIDs[pid] = commName
			}
			c.mu.Unlock()
			if alreadyReported {
				continue
			}
			log.Printf("[ProcessCollector] Detected AI runtime process '%s' (PID %d)", commName, pid)
			// The command line is never sent: it can carry API keys and tokens.
			c.reporter.Submit(reporters.TelemetryEvent{
				EventType:   "process_detected",
				AgentID:     c.cfg.AgentID,
				Domain:      "localhost",
				UserID:      c.processUser(pid),
				RiskScore:   m.Signature.Risk,
				ActionTaken: "monitored",
				Payload: map[string]interface{}{
					"process_name": commName,
					"pid":          pid,
					"ai_tool":      m.Signature.Product,
					"matched_by":   m.By,
				},
			})
		}
	}

	c.reportAgents(agentsNow)

	// Purge terminated processes from seen cache
	c.mu.Lock()
	for pid := range c.seenPIDs {
		if !activePIDs[pid] {
			delete(c.seenPIDs, pid)
		}
	}
	c.mu.Unlock()
}

type agentHit struct {
	comm string
	pid  int
	by   string
	risk float64
	user string
}

// processUser is the account that owns the process (the person running the
// agent), not the account the collector itself runs as - usually root.
func (c *ProcessCollector) processUser(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return ""
		}
		uid := fields[1] // real uid
		c.mu.Lock()
		name, ok := c.userNames[uid]
		c.mu.Unlock()
		if !ok {
			name = uid
			if u, err := user.LookupId(uid); err == nil {
				name = u.Username
			}
			c.mu.Lock()
			c.userNames[uid] = name
			c.mu.Unlock()
		}
		return name
	}
	return ""
}

// reportAgents sends one agent_detected event per AI agent product running
// now: when it first appears, then once per agentHeartbeat while it keeps
// running. Products that stopped are forgotten, so a restart is reported.
func (c *ProcessCollector) reportAgents(now map[string]agentHit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := time.Now()
	for product, hit := range now {
		if last, ok := c.agentsSent[product]; ok && t.Sub(last) < agentHeartbeat {
			continue
		}
		log.Printf("[ProcessCollector] Detected AI agent '%s' (process '%s', PID %d)", product, hit.comm, hit.pid)
		sent := c.reporter.Submit(reporters.TelemetryEvent{
			EventType:   "agent_detected",
			AgentID:     c.cfg.AgentID,
			Domain:      "localhost",
			UserID:      hit.user,
			RiskScore:   hit.risk,
			ActionTaken: "monitored",
			Payload: map[string]interface{}{
				"product":      product,
				"process_name": hit.comm,
				"pid":          hit.pid,
				"matched_by":   hit.by,
			},
		})
		if sent { // a dropped event is retried on the next scan
			c.agentsSent[product] = t
		}
	}
	for product := range c.agentsSent {
		if _, running := now[product]; !running {
			delete(c.agentsSent, product)
		}
	}
}

// RunPeriodic runs the process scanner on a regular schedule.
func (c *ProcessCollector) RunPeriodic(stopChan <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(c.cfg.ScanIntervalSec) * time.Second)
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
