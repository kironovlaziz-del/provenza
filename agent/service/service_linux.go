package service

import (
	"errors"
	"os"
	"os/exec"
	"strings"

	"shadow-ai-agent/config"
)

const unitPath = "/etc/systemd/system/" + Name + ".service"

// Unit is the systemd unit - the same file as deploy/edge/provenza-agent.service
// (a test keeps the two equal), so a machine installed with
// "provenza-agent install" and the Provenza server itself run it the same way.
const Unit = `# Provenza endpoint agent on this host: reports AI tools, agents and local
# models it finds (Discovery). Installed by deploy/scripts/edge.sh (provenza
# edge setup) or by "provenza-agent install", which also write
# /etc/provenza-agent/config.json and its key.
#
# Root, with every capability dropped but two: reading other users' model
# directories (/home/*/.ollama, ...) and raw sockets for ARP/DHCP discovery.
# Events the server has not accepted yet wait in /var/lib/provenza-agent.
[Unit]
Description=Provenza endpoint agent
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/provenza-agent -config /etc/provenza-agent/config.json
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_RAW
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
ReadOnlyPaths=/etc/provenza-agent
StateDirectory=provenza-agent
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`

func requireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo provenza-agent ...)")
	}
	return nil
}

func serviceLabel() string { return Name + ".service (systemd)" }

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(out)) + " (" + err.Error() + ")")
	}
	return nil
}

func stopService() { _ = exec.Command("systemctl", "stop", Name).Run() }

func register(config.Paths) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd not found: run the agent with your init system: provenza-agent run -config /etc/provenza-agent/config.json")
	}
	if err := os.WriteFile(unitPath, []byte(Unit), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", Name); err != nil {
		return err
	}
	return systemctl("restart", Name)
}

func unregister() error {
	_ = exec.Command("systemctl", "disable", "--now", Name).Run()
	err := os.Remove(unitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return err
}

func serviceState() string {
	out, _ := exec.Command("systemctl", "is-active", Name).Output()
	if s := strings.TrimSpace(string(out)); s != "" {
		return Name + ": " + s
	}
	return Name + ": not installed"
}

func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }

func removeBinary(path string) error { return os.Remove(path) }
