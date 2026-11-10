//go:build !windows

package discovery

import (
	"log"
	"net"
	"os"
	"strings"
)

// dnsServerAddresses: the "nameserver" lines in /etc/resolv.conf, and "resolv_conf"
// as the way they were found. Reading the local resolver config is not a scan or a
// probe, it is reading a local file the OS already wrote.
func dnsServerAddresses() ([]string, string) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		log.Printf("[Discovery/DNS] Could not read /etc/resolv.conf: %v", err)
		return nil, "resolv_conf"
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || net.ParseIP(fields[1]) == nil {
			continue
		}
		out = append(out, fields[1])
	}
	return out, "resolv_conf"
}
