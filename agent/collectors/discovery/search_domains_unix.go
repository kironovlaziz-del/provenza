//go:build !windows

package discovery

import (
	"os"
	"strings"
)

// resolverSearchDomains: the "search" and "domain" entries of /etc/resolv.conf.
func resolverSearchDomains() []string {
	var out []string
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "search") || strings.HasPrefix(line, "domain") {
				if fields := strings.Fields(line); len(fields) > 1 {
					out = append(out, fields[1:]...)
				}
			}
		}
	}
	return out
}
