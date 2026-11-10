package discovery

import (
	"context"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// srvProbe is one SRV service to look up under the local domain.
type srvProbe struct {
	service     string // e.g. "ldap"
	proto       string // e.g. "tcp"
	serviceType string // what we report it as: "active_directory", "kerberos", "ldap"
}

// Active Directory advertises its domain controllers via these SRV
// records - this is the standard, documented way clients locate a DC, so
// querying them is ordinary DNS traffic, not probing. _ldap._tcp is the
// definitive "is there an AD/LDAP directory in this domain" signal;
// _kerberos._tcp confirms Kerberos (i.e. almost certainly real AD).
var srvProbes = []srvProbe{
	{"ldap", "tcp", "active_directory"},
	{"kerberos", "tcp", "kerberos"},
	{"gc", "tcp", "active_directory"}, // global catalog - AD-specific
}

// discoverViaDNSSRV finds directory services by SRV lookup under every
// local search domain. Uses only net.Resolver (pure stdlib, no elevated
// privileges, no external deps). Reports each distinct target host.
func discoverViaDNSSRV(rep *Reporter) {
	domains := localSearchDomains()
	if len(domains) == 0 {
		log.Printf("[Discovery/SRV] No local search domain found; skipping SRV discovery")
		return
	}

	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	for _, domain := range domains {
		for _, probe := range srvProbes {
			_, addrs, err := resolver.LookupSRV(ctx, probe.service, probe.proto, domain)
			if err != nil {
				continue // no such record under this domain - normal
			}
			for _, srv := range addrs {
				host := strings.TrimSuffix(srv.Target, ".")
				if host == "" {
					continue
				}
				log.Printf("[Discovery/SRV] Found %s: %s:%d (domain %s)",
					probe.serviceType, host, srv.Port, domain)
				rep.Add(DiscoveredService{
					ServiceType:   probe.serviceType,
					Host:          host,
					Port:          int(srv.Port),
					DiscoveredVia: "dns_srv",
					Details: map[string]interface{}{
						"domain":      domain,
						"srv_service": "_" + probe.service + "._" + probe.proto,
						"priority":    srv.Priority,
						"weight":      srv.Weight,
					},
				})
			}
		}
	}
}

// localSearchDomains returns candidate DNS domains to probe: the
// resolver's search domains (resolverSearchDomains) plus the domain part of the
// machine's own FQDN. Deduplicated, lower-cased.
func localSearchDomains() []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}

	// From the resolver settings: "search corp.local ..." / "domain corp.local"
	// in /etc/resolv.conf, the adapters' DNS suffixes on Windows.
	for _, d := range resolverSearchDomains() {
		add(d)
	}

	// From the host's own FQDN, if it has a domain part.
	if hostname, err := os.Hostname(); err == nil {
		if i := strings.Index(hostname, "."); i != -1 {
			add(hostname[i+1:])
		}
	}

	return out
}
