//go:build !windows

package discovery

import (
	"net"
	"os"
	"strings"
)

// defaultGateway: the default route of /proc/net/route (Linux); nothing where
// there is no such file. "routing_table" is how it was found.
func defaultGateway() (net.IP, string, string) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, "", ""
	}
	lines := strings.Split(string(data), "\n")
	// Header is line 0; each subsequent line is a route. The default
	// route is the one whose Destination is 00000000.
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		iface, destHex, gwHex := fields[0], fields[1], fields[2]
		if destHex != "00000000" {
			continue
		}
		if gwIP := parseLittleEndianHexIP(gwHex); gwIP != nil && !gwIP.IsUnspecified() {
			return gwIP, iface, "routing_table"
		}
	}
	return nil, "", ""
}
