//go:build !linux

package discovery

import "log"

// The raw-socket methods (ARP scan, passive DHCP) use Linux AF_PACKET
// sockets. On Windows and macOS they are not available: discovery there
// runs the unprivileged methods only (DNS SRV, DNS servers, gateway, mDNS,
// LLMNR).

func hasRawSocketCapability() bool { return false }

func discoverViaARPScan(*Reporter) {}

func discoverViaPassiveDHCP(*Reporter) {}

func logCapabilityStatus() {
	log.Printf("[Discovery] ARP scan and passive DHCP are Linux-only - running DNS SRV, DNS servers, " +
		"gateway, mDNS and LLMNR")
}
