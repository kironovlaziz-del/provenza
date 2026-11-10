package discovery

import (
	"log"
	"time"

	"shadow-ai-agent/config"
)

// Collector runs all no-privilege discovery methods on a schedule and
// reports what it finds. It deliberately contains ONLY methods that work
// as an unprivileged process using the Go standard library:
//
//   - DNS SRV lookups         -> Active Directory / Kerberos / LDAP
//   - /etc/resolv.conf        -> in-use DNS servers (Windows: the adapters' settings)
//   - /proc/net/route         -> default gateway, often DHCP/firewall (Windows: the adapters' settings)
//
// Methods that require raw sockets or elevated capabilities (mDNS/LLMNR
// listening, ARP scanning, passive DHCP sniffing) are intentionally NOT
// here: they only work with CAP_NET_RAW and would silently do nothing -
// or crash - on a normal workstation. When a privileged deployment (a
// sensor on a span port) is added, those belong in a clearly separate
// build/module so it's always obvious which methods a given deployment
// can actually perform.
type Collector struct {
	cfg      *config.AgentConfig
	reporter *Reporter
}

func NewCollector(cfg *config.AgentConfig) *Collector {
	logCapabilityStatus()
	return &Collector{
		cfg:      cfg,
		reporter: NewReporter(cfg),
	}
}

// ScanOnce runs every discovery method once and flushes the results.
func (c *Collector) ScanOnce() {
	log.Printf("[Discovery] Starting discovery sweep")

	// Unprivileged methods - always run, work as any user.
	discoverViaDNSSRV(c.reporter)
	discoverDNSServers(c.reporter)
	discoverGateway(c.reporter)
	discoverViaMDNS(c.reporter)
	discoverViaLLMNR(c.reporter)

	// Privileged methods - only when the process actually holds
	// CAP_NET_RAW (probed at runtime, not guessed from uid). If it
	// doesn't, these are skipped silently; the capability status was
	// already logged once at startup so the operator knows why.
	if hasRawSocketCapability() {
		discoverViaARPScan(c.reporter)
		discoverViaPassiveDHCP(c.reporter)
	}

	c.reporter.Flush()
	log.Printf("[Discovery] Discovery sweep complete")
}

// RunPeriodic runs discovery on an interval. Discovery changes slowly
// (infrastructure doesn't move minute to minute), so it runs far less
// often than telemetry collection - default every 15 minutes, or the
// configured DiscoveryIntervalSec if set.
func (c *Collector) RunPeriodic(stopChan <-chan struct{}) {
	interval := time.Duration(c.cfg.DiscoveryIntervalSec) * time.Second
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	ticker := time.NewTicker(interval)
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
