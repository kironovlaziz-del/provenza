package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"shadow-ai-agent/config"
)

// The Windows service: "ProvenzaAgent", automatic start as LocalSystem,
// restarted by the Service Control Manager if it stops unexpectedly.
const (
	winName    = "ProvenzaAgent"
	winDisplay = "Provenza Agent"
	winDesc    = "Reports AI tools, AI agents and local models on this computer to Provenza."
)

// WinServiceName is the name of the Windows service.
const WinServiceName = winName

// LogPath is where the service writes its log (rotated at 10 MB).
func LogPath(p config.Paths) string { return filepath.Join(p.StateDir, "agent.log") }

// ServiceArgs are the arguments the service is started with.
func ServiceArgs(p config.Paths) []string {
	return []string{"run", "-config", p.Config, "-log", LogPath(p)}
}

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("run from an elevated prompt (Run as administrator)")
	}
	return nil
}

func serviceLabel() string { return winName + " (Windows service)" }

func stopService() {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService(winName)
	if err != nil {
		return
	}
	defer s.Close()
	waitStopped(s)
}

func waitStopped(s *mgr.Service) {
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return
	}
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 40; i++ {
		time.Sleep(500 * time.Millisecond)
		if st, err = s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
	}
}

func register(p config.Paths) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	args := ServiceArgs(p)
	s, err := m.OpenService(winName)
	if err == nil { // installed already: point it at this binary and these arguments
		c, err := s.Config()
		if err != nil {
			s.Close()
			return err
		}
		parts := []string{syscall.EscapeArg(p.Binary)}
		for _, a := range args {
			parts = append(parts, syscall.EscapeArg(a))
		}
		c.BinaryPathName = strings.Join(parts, " ")
		c.StartType = mgr.StartAutomatic
		c.DisplayName = winDisplay
		c.Description = winDesc
		if err := s.UpdateConfig(c); err != nil {
			s.Close()
			return err
		}
	} else {
		s, err = m.CreateService(winName, p.Binary, mgr.Config{
			StartType:        mgr.StartAutomatic,
			DisplayName:      winDisplay,
			Description:      winDesc,
			DelayedAutoStart: true,
		}, args...)
		if err != nil {
			return err
		}
	}
	defer s.Close()
	// restart after 5 s, 30 s, then every minute; the count resets daily
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 86400)
	if err := s.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	return nil
}

func unregister() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(winName)
	if err != nil {
		return errors.New(winName + " is not installed")
	}
	defer s.Close()
	waitStopped(s)
	return s.Delete()
}

func serviceState() string {
	m, err := mgr.Connect()
	if err != nil {
		return winName + ": " + err.Error()
	}
	defer m.Disconnect()
	s, err := m.OpenService(winName)
	if err != nil {
		return winName + ": not installed"
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return winName + ": " + err.Error()
	}
	names := map[svc.State]string{
		svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping",
		svc.Running: "running", svc.ContinuePending: "resuming", svc.PausePending: "pausing", svc.Paused: "paused",
	}
	return winName + ": " + names[st.State]
}

// restrictDir: only SYSTEM and Administrators may read the configuration,
// the key and the queue (ProgramData lets every user read by default).
func restrictDir(dir string) error {
	out, err := exec.Command("icacls", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C", "/Q").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeBinary: a running executable cannot be deleted on Windows - when
// uninstall runs from the installed copy, it is deleted a moment later.
func removeBinary(path string) error {
	self, _ := os.Executable()
	if same(self, path) {
		cmd := exec.Command("cmd.exe")
		// the command line as cmd.exe reads it, not escaped again by Go
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
			CmdLine: `cmd.exe /C ping -n 3 127.0.0.1 >NUL & del /F /Q "` + path + `" & rmdir "` + filepath.Dir(path) + `"`}
		return cmd.Start()
	}
	err := os.Remove(path)
	_ = os.Remove(filepath.Dir(path)) // only when empty
	return err
}
