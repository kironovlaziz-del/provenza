// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"net"
	"os"
	"strings"
)

// upstreamFromResolvConf reads nameservers from /etc/resolv.conf. Returns
// nil on failure so the caller can fall back to a public resolver.
func upstreamFromResolvConf() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil {
				out = append(out, net.JoinHostPort(ip.String(), "53"))
			}
		}
	}
	return out
}
