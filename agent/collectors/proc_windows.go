package collectors

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listProcesses takes a Toolhelp snapshot of the processes; the command
// line of each comes from NtQueryInformationProcess (Windows 8.1 and
// later). Run as a service (LocalSystem) the agent can read almost every
// process; protected processes keep only their executable name.
func listProcesses() ([]procInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}
	var out []procInfo
	for {
		pid := int(entry.ProcessID)
		if pid > 4 { // 0: System Idle, 4: System
			p := procInfo{PID: pid, Comm: windows.UTF16ToString(entry.ExeFile[:])}
			p.Argv = commandLine(entry.ProcessID)
			if len(p.Argv) == 0 {
				p.Argv = []string{p.Comm}
			}
			out = append(out, p)
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return out, nil
		}
	}
	return out, nil
}

func commandLine(pid uint32) []string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)

	var size uint32
	_ = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, nil, 0, &size)
	if size == 0 || size > 1<<20 {
		return nil
	}
	buf := make([]byte, size)
	if err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
		unsafe.Pointer(&buf[0]), size, &size); err != nil {
		return nil
	}
	line := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0])).String()
	argv, err := windows.DecomposeCommandLine(line)
	if err != nil {
		return nil
	}
	return argv
}

// processUID is the SID of the account that owns the process.
func processUID(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}

// accountName: the account name of a SID, without the domain - the same
// form as on Linux and macOS.
func accountName(sid string) string {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return sid
	}
	account, _, _, err := s.LookupAccount("")
	if err != nil {
		return sid
	}
	return account
}

// newBehaviorProbe: on Windows the "api" signal - "netstat -ano" lists
// connections with their process - and the "sdk" signal, from the loaded
// modules of the process (Toolhelp). The environment of another process is
// not read: that needs its memory.
func newBehaviorProbe(apiIPs map[string]string) behaviorProbe {
	conn := connProbe{}
	if len(apiIPs) > 0 {
		var conns []pidConn
		for _, proto := range []string{"TCP", "TCPv6"} {
			if out, err := commandOutput("netstat", "-ano", "-p", proto); err == nil {
				conns = append(conns, parseNetstat(out)...)
			}
		}
		conn = newConnProbe(conns, apiIPs)
	}
	return winProbe{conn: conn}
}

type winProbe struct{ conn connProbe }

func (w winProbe) inspect(p procInfo, interpreted bool) behaviorSignals {
	s := w.conn.inspect(p, interpreted)
	// like on Linux: modules are listed only for likely agents (interpreters,
	// or a process already talking to an LLM API)
	if interpreted || len(s.APIHosts) > 0 {
		s.SDKs = sdkMarkersFromPaths(loadedModules(p.PID))
	}
	return s
}

// loadedModules: the file paths of the modules (DLLs, .pyd, the executable)
// loaded in a process. Nothing when the process cannot be read (protected, or
// another bitness): only the paths are looked at, and only for the markers.
func loadedModules(pid int) []string {
	var snap windows.Handle
	var err error
	for try := 0; try < 5; try++ { // ERROR_BAD_LENGTH: the module list changed while it was taken
		snap, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(pid))
		if !errors.Is(err, windows.ERROR_BAD_LENGTH) {
			break
		}
	}
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var m windows.ModuleEntry32
	m.Size = uint32(unsafe.Sizeof(m))
	if err := windows.Module32First(snap, &m); err != nil {
		return nil
	}
	var out []string
	for len(out) < 50000 {
		out = append(out, windows.UTF16ToString(m.ExePath[:]))
		if err := windows.Module32Next(snap, &m); err != nil {
			break
		}
	}
	return out
}
