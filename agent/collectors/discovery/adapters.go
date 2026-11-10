package discovery

import (
	"net"
	"sort"
)

// adapterInfo: what the network settings of one adapter say (Windows:
// GetAdaptersAddresses; the choosing below is portable so that it is tested everywhere).
type adapterInfo struct {
	Name     string
	Up       bool
	Loopback bool
	Metric   uint32 // IPv4 metric: the lower, the more preferred
	DNS      []net.IP
	Gateways []net.IP
	Suffixes []string
}

// usableDNS: a DNS server worth reporting. Windows lists, for an adapter
// without IPv6 DNS settings, the site-local fec0:0:0:ffff::1-3 placeholders: they are
// not servers. Loopback (a local stub) and link-local are skipped too.
func usableDNS(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.To4() == nil && len(ip) == net.IPv6len && ip[0] == 0xfe && ip[1]&0xc0 == 0xc0 { // fec0::/10
		return false
	}
	return true
}

// dnsFromAdapters: the DNS servers of the adapters that are up, preferred
// adapter first, each once.
func dnsFromAdapters(as []adapterInfo) []string {
	as = upAdapters(as)
	var out []string
	seen := map[string]bool{}
	for _, a := range as {
		for _, ip := range a.DNS {
			if s := ip.String(); usableDNS(ip) && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// gatewayFromAdapters: the default gateway of the most preferred adapter
// that has one (an IPv4 gateway before an IPv6 one).
func gatewayFromAdapters(as []adapterInfo) (net.IP, string) {
	as = upAdapters(as)
	for _, v4 := range []bool{true, false} {
		for _, a := range as {
			for _, gw := range a.Gateways {
				if gw == nil || gw.IsUnspecified() || (gw.To4() != nil) != v4 {
					continue
				}
				return gw, a.Name
			}
		}
	}
	return nil, ""
}

// suffixesFromAdapters: the DNS suffixes of the adapters that are up.
func suffixesFromAdapters(as []adapterInfo) []string {
	var out []string
	for _, a := range upAdapters(as) {
		out = append(out, a.Suffixes...)
	}
	return out
}

// upAdapters: the adapters that are up and are not the loopback, by metric.
func upAdapters(as []adapterInfo) []adapterInfo {
	var out []adapterInfo
	for _, a := range as {
		if a.Up && !a.Loopback {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Metric < out[j].Metric })
	return out
}
