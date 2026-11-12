// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package connect

import (
	"fmt"
	"strconv"
	"strings"
)

// What agent mode needs on Windows to start at sign-in. The text is built on
// every system so that it is tested on every system; only Windows runs it.

// runKey: the programs that start when this user signs in (HKCU: this user only).
const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

func (o Options) runValueName() string { return fmt.Sprintf("ProvenzaAgent%d", o.AgentID) }

// AutostartCommand: what the sign-in entry runs: `provenza-proxy agent-start`
// starts agent mode in the background (no console window to close by mistake) and exits.
func (o Options) AutostartCommand() string {
	return strings.Join([]string{winQuote(o.Binary), "agent-start",
		"-agent-id", strconv.FormatInt(o.AgentID, 10),
		"-identity", winQuote(o.Identity),
		"-port", strconv.Itoa(o.Port),
		"-proxy", winQuote(o.Proxy)}, " ")
}

func (o Options) runKeyAddArgs() []string {
	return []string{"add", runKey, "/v", o.runValueName(), "/t", "REG_SZ", "/d", o.AutostartCommand(), "/f"}
}

// winQuote: one argument of a Windows command line, quoted the way
// CommandLineToArgvW reads it back.
func winQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\v\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			slashes++
			b.WriteRune(r)
			continue
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes+1)) // the slashes before a quote are doubled, then the quote escaped
		}
		slashes = 0
		b.WriteRune(r)
	}
	b.WriteString(strings.Repeat(`\`, slashes)) // trailing slashes, before the closing quote
	b.WriteByte('"')
	return b.String()
}

// runValue: one value of the Run key, as `reg query` lists it.
type runValue struct{ Name, Data string }

// parseRunValues: the REG_SZ / REG_EXPAND_SZ values in `reg query <key>` output
// ("    <name>    REG_SZ    <data>"; the type is the same in every language).
func parseRunValues(out string) []runValue {
	var vals []runValue
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		for _, typ := range []string{"    REG_SZ    ", "    REG_EXPAND_SZ    "} {
			i := strings.Index(line, typ)
			if i < 0 {
				continue
			}
			name := strings.TrimSpace(line[:i])
			if name != "" {
				vals = append(vals, runValue{Name: name, Data: strings.TrimSpace(line[i+len(typ):])})
			}
			break
		}
	}
	return vals
}

// parseListener: the pid listening on addr in `netstat -ano -p TCP` output
// ("  TCP    127.0.0.1:8480    0.0.0.0:0    LISTENING    6744"; the state word
// is translated in some languages, so the foreign address 0.0.0.0:0 is what
// marks a listener).
func parseListener(out, addr string) int {
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.EqualFold(f[0], "TCP") || f[1] != addr || f[2] != "0.0.0.0:0" {
			continue
		}
		if pid, err := strconv.Atoi(f[len(f)-1]); err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}
