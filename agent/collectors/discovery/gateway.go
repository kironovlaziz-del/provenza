package discovery

import (
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"strings"
)

// discoverGateway reports the machine's default gateway (defaultGateway:
// /proc/net/route on Linux, the adapters' settings on Windows). The gateway
// is frequently also the DHCP server and/or the network firewall, so
// surfacing it gives the admin a starting point for those. A local table
// read - no scanning, no privileges.
func discoverGateway(rep *Reporter) {
	gwIP, iface, via := defaultGateway()
	if gwIP == nil || gwIP.IsUnspecified() {
		return // none, or not readable here: not worth alarming about
	}
	details := map[string]interface{}{"interface": iface}
	if names, err := net.LookupAddr(gwIP.String()); err == nil && len(names) > 0 {
		details["ptr"] = strings.TrimSuffix(names[0], ".")
	}

	log.Printf("[Discovery/GW] Found default gateway: %s (via %s)", gwIP, iface)
	rep.Add(DiscoveredService{
		ServiceType:   "gateway",
		Host:          gwIP.String(),
		DiscoveredVia: via,
		Details:       details,
	})
}

// parseLittleEndianHexIP parses the 8-hex-char, little-endian IPv4 form
// used in /proc/net/route (e.g. "0100A8C0" -> 192.168.0.1).
func parseLittleEndianHexIP(h string) net.IP {
	if len(h) != 8 {
		return nil
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil
	}
	// The field is the address in native (little-endian) byte order.
	v := binary.LittleEndian.Uint32(b)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
