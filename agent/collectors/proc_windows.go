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

// newBehaviorProbe: on Windows only the "api" signal - "netstat -ano"
// lists connections with their process. The environment and the loaded
// libraries of another process are not read.
func newBehaviorProbe(apiIPs map[string]string) behaviorProbe {
	if len(apiIPs) == 0 {
		return connProbe{}
	}
	var conns []pidConn
	for _, proto := range []string{"TCP", "TCPv6"} {
		if out, err := commandOutput("netstat", "-ano", "-p", proto); err == nil {
			conns = append(conns, parseNetstat(out)...)
		}
	}
	return newConnProbe(conns, apiIPs)
}
