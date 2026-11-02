package service

import (
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"

	"shadow-ai-agent/config"
)

// The LaunchDaemon: started at boot as root, restarted if it exits.
const (
	daemonLabel = "com.provenza.agent"
	plistPath   = "/Library/LaunchDaemons/" + daemonLabel + ".plist"
	// LogPath is where the daemon writes its log (rotated at 10 MB).
	LogPath = "/Library/Logs/provenza-agent.log"
)

// Plist is the LaunchDaemon property list for paths.
func Plist(p config.Paths) string {
	args := []string{p.Binary, "run", "-config", p.Config, "-log", LogPath}
	var b strings.Builder
	for _, a := range args {
		fmt.Fprintf(&b, "\t\t<string>%s</string>\n", html.EscapeString(a))
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + daemonLabel + `</string>
	<key>ProgramArguments</key>
	<array>
` + b.String() + `	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LowPriorityIO</key>
	<true/>
</dict>
</plist>
`
}

func requireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo provenza-agent ...)")
	}
	return nil
}

func serviceLabel() string { return daemonLabel + " (LaunchDaemon)" }

func launchctl(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(out)) + " (" + err.Error() + ")")
	}
	return nil
}

func stopService() { _ = exec.Command("launchctl", "bootout", "system/"+daemonLabel).Run() }

func register(p config.Paths) error {
	if err := os.WriteFile(plistPath, []byte(Plist(p)), 0o644); err != nil {
		return err
	}
	_ = os.Chown(plistPath, 0, 0) // root:wheel, or launchd refuses it
	_ = launchctl("enable", "system/"+daemonLabel)
	if err := launchctl("bootstrap", "system", plistPath); err != nil {
		// older macOS
		if err2 := launchctl("load", "-w", plistPath); err2 != nil {
			return err
		}
	}
	return nil
}

func unregister() error {
	stopService()
	return os.Remove(plistPath)
}

func serviceState() string {
	out, err := exec.Command("launchctl", "print", "system/"+daemonLabel).Output()
	if err != nil {
		return daemonLabel + ": not loaded"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, "state = ") {
			return daemonLabel + ": " + strings.TrimPrefix(l, "state = ")
		}
	}
	return daemonLabel + ": loaded"
}

func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }

func removeBinary(path string) error { return os.Remove(path) }
