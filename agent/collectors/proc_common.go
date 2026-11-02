package collectors

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// procInfo is one running process, as each operating system lists it
// (proc_linux.go, proc_windows.go, proc_darwin.go).
type procInfo struct {
	PID  int
	Comm string   // executable name ("node", "ollama.exe", "Cursor")
	Argv []string // command line; never leaves the machine
	// UID is the owner's account id (Linux and macOS uid, Windows SID),
	// resolved to a name only for processes that are reported.
	UID string
	// User is the owner's name when the listing already has it.
	User string
	// Env holds the environment of the process when the operating system
	// exposes it cheaply (macOS); only variable names are ever compared.
	Env []byte
}

// behaviorProbe reads the behavioral signals (behavior.go) of a process no
// signature matched. One probe is built per scan.
type behaviorProbe interface {
	inspect(p procInfo, interpreted bool) behaviorSignals
}

// pidConn is an HTTPS connection of a process to a remote address.
type pidConn struct {
	PID int
	IP  string
}

// connProbe is the probe of Windows and macOS: the "api" signal from the
// table of connections with their owning processes (netstat, lsof).
type connProbe struct {
	hosts map[int][]string // pid -> LLM API hosts it is connected to
}

func newConnProbe(conns []pidConn, apiIPs map[string]string) connProbe {
	byPID := map[int]map[string]bool{}
	for _, c := range conns {
		host, ok := apiIPs[c.IP]
		if !ok || c.PID <= 0 {
			continue
		}
		if byPID[c.PID] == nil {
			byPID[c.PID] = map[string]bool{}
		}
		byPID[c.PID][host] = true
	}
	out := connProbe{hosts: map[int][]string{}}
	for pid, set := range byPID {
		for h := range set {
			out.hosts[pid] = append(out.hosts[pid], h)
		}
		sort.Strings(out.hosts[pid])
	}
	return out
}

func (p connProbe) inspect(proc procInfo, interpreted bool) behaviorSignals {
	s := behaviorSignals{APIHosts: p.hosts[proc.PID]}
	if len(proc.Env) > 0 && (interpreted || len(s.APIHosts) > 0) {
		s.EnvKeys = envKeyNames(proc.Env)
	}
	return s
}

// parseNetstat reads "netstat -ano -p TCP" (and TCPv6) output of Windows:
//
//	TCP    10.0.0.5:51234     104.18.32.47:443     ESTABLISHED     4312
//	TCP    [2001:db8::5]:51240  [2606:4700::6810]:443  ESTABLISHED  4312
//
// and returns the connections to port 443 with their process. The state
// column is translated on non-English Windows, so it is not compared: a
// listening socket has no remote port 443, and TIME_WAIT belongs to PID 0.
func parseNetstat(out string) []pidConn {
	var conns []pidConn
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || !strings.EqualFold(f[0], "TCP") {
			continue
		}
		pid, err := strconv.Atoi(f[len(f)-1])
		if err != nil || pid <= 0 {
			continue
		}
		host, port, err := net.SplitHostPort(f[2])
		if err != nil || port != "443" {
			continue
		}
		if ip := normalizeIP(host); ip != "" {
			conns = append(conns, pidConn{PID: pid, IP: ip})
		}
	}
	return conns
}

// parseLsof reads "lsof -nP -iTCP -sTCP:ESTABLISHED -F pn" output of
// macOS: a "p<pid>" line, then "n<local>-><remote>" lines for that process.
func parseLsof(out string) []pidConn {
	var conns []pidConn
	pid := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			_, remote, ok := strings.Cut(line[1:], "->")
			if !ok || pid <= 0 {
				continue
			}
			host, port, err := net.SplitHostPort(remote)
			if err != nil || port != "443" {
				continue
			}
			if ip := normalizeIP(host); ip != "" {
				conns = append(conns, pidConn{PID: pid, IP: ip})
			}
		}
	}
	return conns
}

// normalizeIP: the address in the form the resolver keys it by (IPv4 for
// IPv4-mapped IPv6), or "" when it is not an address.
func normalizeIP(s string) string {
	ip := net.ParseIP(strings.Trim(s, "[]"))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// parseProcArgs2 reads the kern.procargs2 sysctl of macOS: argc (int32),
// the executable path, NUL padding, argc arguments, then the environment.
func parseProcArgs2(buf []byte) (exe string, argv []string, env []byte) {
	if len(buf) < 4 {
		return "", nil, nil
	}
	argc := int(binary.LittleEndian.Uint32(buf[:4]))
	rest := buf[4:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return string(rest), nil, nil
	}
	exe = string(rest[:end])
	rest = rest[end:]
	for len(rest) > 0 && rest[0] == 0 { // padding after the path
		rest = rest[1:]
	}
	for i := 0; i < argc && len(rest) > 0; i++ {
		end = bytes.IndexByte(rest, 0)
		if end < 0 {
			argv = append(argv, string(rest))
			return exe, argv, nil
		}
		argv = append(argv, string(rest[:end]))
		rest = rest[end+1:]
	}
	// the environment: NUL-separated "NAME=value" strings, ending at "\0\0"
	if end = bytes.Index(rest, []byte{0, 0}); end >= 0 {
		rest = rest[:end+1]
	}
	return exe, argv, rest
}

// commandOutput runs a system tool (netstat, lsof) with a time limit.
func commandOutput(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}
