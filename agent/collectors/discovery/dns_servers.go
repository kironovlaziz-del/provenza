package discovery

import (
	"log"
	"net"
	"strings"
)

// discoverDNSServers reports the DNS servers this machine is configured
// to use (dnsServerAddresses: resolv.conf, or the adapters' settings on
// Windows). These are real, in-use infrastructure services - reading the
// local resolver config is not a scan or a probe.
func discoverDNSServers(rep *Reporter) {
	addrs, via := dnsServerAddresses()
	for _, ip := range addrs {
		// 127.0.0.53 is systemd-resolved's local stub, not a real
		// upstream DNS server - reporting it as network infrastructure
		// would be misleading, so skip loopback resolvers.
		if p := net.ParseIP(ip); p == nil || p.IsLoopback() {
			continue
		}

		details := map[string]interface{}{}
		// A reverse lookup often reveals the server's real hostname,
		// which is far more useful to an admin than a bare IP.
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			details["ptr"] = strings.TrimSuffix(names[0], ".")
		}

		log.Printf("[Discovery/DNS] Found DNS server: %s", ip)
		rep.Add(DiscoveredService{
			ServiceType:   "dns",
			Host:          ip,
			Port:          53,
			DiscoveredVia: via,
			Details:       details,
		})
	}
}
