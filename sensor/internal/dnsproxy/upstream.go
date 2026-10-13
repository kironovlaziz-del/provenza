// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package dnsproxy

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// Upstreams reads the host's resolvers from resolv.conf. The sensor itself
// is not governed, so it may use them (including a local stub).
func Upstreams(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"127.0.0.53:53"}
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil {
				out = append(out, net.JoinHostPort(ip.String(), "53"))
			}
		}
	}
	if len(out) == 0 {
		out = []string{"127.0.0.53:53"}
	}
	return out
}
