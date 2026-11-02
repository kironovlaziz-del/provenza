package collectors

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// listProcesses reads /proc. comm is /proc/<pid>/comm, argv the NUL-split
// /proc/<pid>/cmdline (empty for kernel threads).
func listProcesses() ([]procInfo, error) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()
	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	var out []procInfo
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}
		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		p := procInfo{PID: pid, Comm: strings.TrimSpace(string(commBytes))}
		if cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); len(cmdline) > 0 {
			p.Argv = strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		}
		out = append(out, p)
	}
	return out, nil
}

// processUID is the real uid of a process (/proc/<pid>/status).
func processUID(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			if fields := strings.Fields(line); len(fields) >= 2 {
				return fields[1]
			}
			return ""
		}
	}
	return ""
}

func accountName(uid string) string {
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}

// linuxProbe: all three signals, from /proc (behavior.go).
type linuxProbe struct {
	sockets, apiIPs map[string]string
}

func newBehaviorProbe(apiIPs map[string]string) behaviorProbe {
	return linuxProbe{sockets: llmSockets(httpsSockets(), apiIPs), apiIPs: apiIPs}
}

func (l linuxProbe) inspect(p procInfo, interpreted bool) behaviorSignals {
	return inspectProcess(p.PID, interpreted, l.sockets, l.apiIPs, os.ReadFile, os.Readlink, listDir)
}
