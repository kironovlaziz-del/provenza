// Package service installs the agent as a system service: a systemd unit
// on Linux, a LaunchDaemon on macOS, a Windows service - with its
// configuration and key in the system's place for them (config.Paths).
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"shadow-ai-agent/config"
)

// Name is the service name: the systemd unit and the Windows service.
const Name = "provenza-agent"

// Options of "provenza-agent install".
type Options struct {
	Server    string // https://provenza.example.com (or the full ingest URL)
	Key       string // the Ingestion Source key
	AgentID   string // the name the machine is listed under ("" = host name)
	Discovery bool   // network discovery
}

// IngestURL turns a server address into the ingest endpoint. A full
// ".../shadow-ai/ingest" URL is kept. Plain HTTP is accepted only for this
// machine itself (a test server): the key must not cross a network in clear.
func IngestURL(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", errors.New("--server is required (https://your-provenza)")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("--server %q is not a URL", server)
	}
	host := u.Hostname()
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return "", fmt.Errorf("--server must be https:// (http only for localhost)")
	}
	u.RawQuery, u.Fragment = "", ""
	p := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(p, "/shadow-ai/ingest") {
		p += "/api/v1/shadow-ai/ingest"
	}
	u.Path = p
	return u.String(), nil
}

// fileConfig is what install writes to config.json. Model folders are left
// to the defaults of the system (config.DefaultModelSearchPaths).
type fileConfig struct {
	APIURL               string `json:"api_url"`
	IngestionKeyFile     string `json:"ingestion_key_file"`
	AgentID              string `json:"agent_id,omitempty"`
	ScanIntervalSec      int    `json:"scan_interval_sec"`
	BatchIntervalSec     int    `json:"batch_interval_sec"`
	BatchSize            int    `json:"batch_size"`
	HeartbeatSec         int    `json:"heartbeat_sec"`
	StateDir             string `json:"state_dir"`
	DiscoveryEnabled     bool   `json:"discovery_enabled"`
	DiscoveryIntervalSec int    `json:"discovery_interval_sec"`
}

// RenderConfig is the config.json for paths and options.
func RenderConfig(p config.Paths, apiURL string, o Options) ([]byte, error) {
	b, err := json.MarshalIndent(fileConfig{
		APIURL:               apiURL,
		IngestionKeyFile:     p.KeyFile,
		AgentID:              o.AgentID,
		ScanIntervalSec:      30,
		BatchIntervalSec:     10,
		BatchSize:            50,
		HeartbeatSec:         900,
		StateDir:             p.StateDir,
		DiscoveryEnabled:     o.Discovery,
		DiscoveryIntervalSec: 900,
	}, "", "  ")
	return append(b, '\n'), err
}

// Install puts the running executable, the configuration and the key in
// place, registers the service and starts it. Run again, it upgrades: a
// configuration already there is kept unless --server or --key is given.
func Install(o Options, out io.Writer) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	p := config.InstallPaths(runtime.GOOS)

	_, statErr := os.Stat(p.Config)
	haveConfig := statErr == nil
	if !haveConfig && (o.Server == "" || o.Key == "") {
		return errors.New("first install: --server and --key are required")
	}
	var cfgData []byte
	if o.Server != "" {
		apiURL, err := IngestURL(o.Server)
		if err != nil {
			return err
		}
		if cfgData, err = RenderConfig(p, apiURL, o); err != nil {
			return err
		}
	} else if o.Key != "" || o.AgentID != "" || o.Discovery {
		fmt.Fprintln(out, "note: without --server the existing configuration is kept as it is")
	}

	stopService() // an upgrade: the old binary must not be running
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := copyBinary(self, p.Binary); err != nil {
		return fmt.Errorf("install %s: %w", p.Binary, err)
	}
	fmt.Fprintf(out, "binary:  %s\n", p.Binary)

	for _, d := range []string{filepath.Dir(p.Config), p.StateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if cfgData != nil {
		if err := writePrivate(p.Config, cfgData); err != nil {
			return err
		}
		fmt.Fprintf(out, "config:  %s\n", p.Config)
	}
	if o.Key != "" {
		if err := writePrivate(p.KeyFile, []byte(strings.TrimSpace(o.Key)+"\n")); err != nil {
			return err
		}
		fmt.Fprintf(out, "key:     %s (administrators only)\n", p.KeyFile)
	}
	if err := restrictDir(filepath.Dir(p.Config)); err != nil {
		return err
	}
	if err := register(p); err != nil {
		return fmt.Errorf("register the service: %w", err)
	}
	fmt.Fprintf(out, "service: %s registered and started\n", serviceLabel())
	fmt.Fprintln(out, "The machine appears under Discovery -> Devices within a minute.")
	return nil
}

// Uninstall stops and removes the service and the binary; purge also
// removes the configuration, the key and the queue.
func Uninstall(purge bool, out io.Writer) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	p := config.InstallPaths(runtime.GOOS)
	if err := unregister(); err != nil {
		fmt.Fprintf(out, "service: %v\n", err)
	} else {
		fmt.Fprintf(out, "service: %s removed\n", serviceLabel())
	}
	if err := removeBinary(p.Binary); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(out, "binary:  %v\n", err)
	} else {
		fmt.Fprintf(out, "binary:  %s removed\n", p.Binary)
	}
	if purge {
		for _, d := range []string{p.StateDir, filepath.Dir(p.Config)} {
			_ = os.RemoveAll(d)
		}
		fmt.Fprintf(out, "config:  %s removed\n", filepath.Dir(p.Config))
	} else {
		fmt.Fprintf(out, "config:  kept in %s (--purge removes it)\n", filepath.Dir(p.Config))
	}
	return nil
}

// Status prints the service state, the configuration and the queue.
func Status(out io.Writer) error {
	p := config.InstallPaths(runtime.GOOS)
	fmt.Fprintf(out, "service: %s\n", serviceState())
	if data, err := os.ReadFile(p.Config); err == nil {
		var c fileConfig
		if json.Unmarshal(data, &c) == nil {
			fmt.Fprintf(out, "server:  %s\n", c.APIURL)
		}
		fmt.Fprintf(out, "config:  %s\n", p.Config)
	} else {
		fmt.Fprintf(out, "config:  none at %s\n", p.Config)
	}
	q := filepath.Join(p.StateDir, "queue")
	if entries, err := os.ReadDir(q); err == nil {
		n := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".batch.json") {
				n++
			}
		}
		fmt.Fprintf(out, "queue:   %d undelivered batch(es) in %s\n", n, q)
	}
	return nil
}

func copyBinary(src, dst string) error {
	if same(src, dst) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, in); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := replaceFile(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func same(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(ra), filepath.Clean(rb))
}

func writePrivate(path string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return replaceFile(tmp, path)
}

// replaceFile moves tmp over dst (MoveFileEx with replace on Windows).
func replaceFile(tmp, dst string) error { return os.Rename(tmp, dst) }
