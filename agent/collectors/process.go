package collectors

import (
	"log"
	"os"
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
	resolver   *apiResolver
	mu         sync.Mutex
	// listErrLogged: a failed process listing is logged once
	listErrLogged bool
}

// NewProcessCollector creates an instance of the process monitor.
func NewProcessCollector(cfg *config.AgentConfig, rep *reporters.Reporter) *ProcessCollector {
	return &ProcessCollector{
		cfg:        cfg,
		reporter:   rep,
		seenPIDs:   make(map[int]string),
		agentsSent: make(map[string]time.Time),
		userNames:  make(map[string]string),
		resolver:   newAPIResolver(),
	}
}

// ScanOnce lists the running processes (per operating system: /proc on
// Linux, the Toolhelp snapshot on Windows, sysctl on macOS - see
// proc_<os>.go) and reports the AI runtimes and agents among them.
func (c *ProcessCollector) ScanOnce() {
	procs, err := listProcesses()
	if err != nil {
		c.logListError(err)
		return
	}

	activePIDs := make(map[int]bool)
	agentsNow := make(map[string]agentHit)
	apiIPs := c.resolver.addresses()
	probe := newBehaviorProbe(apiIPs)
	self := os.Getpid()

	for _, p := range procs {
		activePIDs[p.PID] = true
		commName := p.Comm

		matches := MatchProcess(commName, p.Argv)
		if len(matches) == 0 && p.PID != self && len(p.Argv) > 0 && !behaviorIgnore[normalizeName(commName)] {
			c.inspectUnknown(p, probe, agentsNow)
		}
		for _, m := range matches {
			if m.Signature.Kind == "agent" {
				if _, seen := agentsNow[m.Signature.Product]; !seen {
					agentsNow[m.Signature.Product] = agentHit{comm: commName, pid: p.PID, by: m.By, risk: m.Signature.Risk,
						user: c.processUser(p)}
				}
				continue
			}
			c.mu.Lock()
			alreadyReported := c.seenPIDs[p.PID] == commName
			if !alreadyReported {
				c.seenPIDs[p.PID] = commName
			}
			c.mu.Unlock()
			if alreadyReported {
				continue
			}
			log.Printf("[ProcessCollector] Detected AI runtime process '%s' (PID %d)", commName, p.PID)
			// The command line is never sent: it can carry API keys and tokens.
			c.reporter.Submit(reporters.TelemetryEvent{
				EventType:   "process_detected",
				AgentID:     c.cfg.AgentID,
				Domain:      "localhost",
				UserID:      c.processUser(p),
				RiskScore:   m.Signature.Risk,
				ActionTaken: "monitored",
				Payload: map[string]interface{}{
					"process_name": commName,
					"pid":          p.PID,
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

// logListError logs a failed process listing once, not on every scan.
func (c *ProcessCollector) logListError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.listErrLogged {
		c.listErrLogged = true
		log.Printf("[ProcessCollector] cannot list processes: %v", err)
	}
}

type agentHit struct {
	comm  string
	pid   int
	by    string
	risk  float64
	user  string
	extra map[string]interface{} // behavioral signals, for unrecognized agents
}

// processUser is the account that owns the process (the person running the
// agent), not the account the collector itself runs as - usually root or
// SYSTEM. Names are cached per account id.
func (c *ProcessCollector) processUser(p procInfo) string {
	if p.User != "" {
		return p.User
	}
	if p.UID == "" {
		p.UID = processUID(p.PID)
		if p.UID == "" {
			return ""
		}
	}
	c.mu.Lock()
	name, ok := c.userNames[p.UID]
	c.mu.Unlock()
	if !ok {
		name = accountName(p.UID)
		c.mu.Lock()
		c.userNames[p.UID] = name
		c.mu.Unlock()
	}
	return name
}

func (h agentHit) payload(product string) map[string]interface{} {
	p := map[string]interface{}{
		"product":      product,
		"process_name": h.comm,
		"pid":          h.pid,
		"matched_by":   h.by,
	}
	for k, v := range h.extra {
		p[k] = v
	}
	return p
}

// inspectUnknown looks for behavioral signals in a process no signature
// matched (see behavior.go) and records it as an unrecognized agent.
func (c *ProcessCollector) inspectUnknown(p procInfo, probe behaviorProbe, agentsNow map[string]agentHit) {
	interpreted := interpreters[interpreterName(p.Argv[0])]
	sig := probe.inspect(p, interpreted)
	if !sig.found() {
		return
	}
	product := customProductID(p.Comm, p.Argv)
	if _, seen := agentsNow[product]; seen {
		return
	}
	conf := sig.confidence()
	risk := 0.5
	if conf == "high" {
		risk = 0.6
	}
	agentsNow[product] = agentHit{comm: p.Comm, pid: p.PID, by: "behavior", risk: risk, user: c.processUser(p),
		extra: map[string]interface{}{
			"confidence": conf,
			"api_hosts":  sig.APIHosts,
			"env_keys":   sig.EnvKeys, // names only, never values
			"sdks":       sig.SDKs,
		}}
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
			Payload:     hit.payload(product),
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
