package collectors

import (
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// listProcesses lists processes with the kern.proc.all sysctl; the command
// line and environment of each come from kern.procargs2. Run as a
// LaunchDaemon (root) the agent reads every process except those macOS
// protects; those keep only their short name.
func listProcesses() ([]procInfo, error) {
	kprocs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	out := make([]procInfo, 0, len(kprocs))
	for _, k := range kprocs {
		pid := int(k.Proc.P_pid)
		if pid <= 0 {
			continue
		}
		p := procInfo{
			PID:  pid,
			Comm: unix.ByteSliceToString(k.Proc.P_comm[:]),
			UID:  strconv.FormatUint(uint64(k.Eproc.Ucred.Uid), 10),
		}
		if raw, err := unix.SysctlRaw("kern.procargs2", pid); err == nil {
			exe, argv, env := parseProcArgs2(raw)
			if exe != "" {
				p.Comm = filepath.Base(exe) // P_comm is cut at 16 characters
			}
			p.Argv, p.Env = argv, env
		}
		if len(p.Argv) == 0 {
			p.Argv = []string{p.Comm}
		}
		out = append(out, p)
	}
	return out, nil
}

func processUID(int) string { return "" } // the listing has the uid

// accountName: os/user without cgo reads /etc/passwd, which on macOS holds
// only system accounts; "id -un" asks Directory Services.
func accountName(uid string) string {
	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		return u.Username
	}
	if out, err := commandOutput("id", "-un", uid); err == nil {
		if name := strings.TrimSpace(out); name != "" {
			return name
		}
	}
	return uid
}

// newBehaviorProbe: on macOS the "api" signal from lsof, and the "env"
// signal from kern.procargs2 (names only). Loaded libraries are not read.
func newBehaviorProbe(apiIPs map[string]string) behaviorProbe {
	if len(apiIPs) == 0 {
		return connProbe{}
	}
	// lsof exits 1 when nothing matches: the output decides, not the status
	out, _ := commandOutput("lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pn")
	return newConnProbe(parseLsof(out), apiIPs)
}
