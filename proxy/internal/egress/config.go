// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// LocalSecret is a credential this proxy injects from its own configuration
// (a route with credential_source "local"): the Provenza server never sees it.
type LocalSecret struct {
	Header    string `json:"header,omitempty"`     // default: the route's auth_header
	ValueEnv  string `json:"value_env,omitempty"`  // read from this environment variable
	ValueFile string `json:"value_file,omitempty"` // or from this file (e.g. a mounted Kubernetes Secret)
	// Upstream: the only origin (https://host[:port]) it is sent to - set it, so a
	// server that points the route elsewhere does not take the credential along
	Upstream string `json:"upstream,omitempty"`
}

// Config of the proxy (JSON: the standard library has no YAML).
type Config struct {
	// SHA256: of the file's bytes as read - what a sensor on this host pins (sensorreport.go)
	SHA256           string                 `json:"-"`
	ServerURL        string                 `json:"server_url"`
	ProxyKeyEnv      string                 `json:"proxy_key_env,omitempty"`      // default PROVENZA_PROXY_KEY
	ProxyKeyFile     string                 `json:"proxy_key_file,omitempty"`     // instead of the environment
	Listen           string                 `json:"listen,omitempty"`             // default 127.0.0.1:8443
	LocalSecrets     map[string]LocalSecret `json:"local_secrets,omitempty"`      // by route slug
	UpstreamTimeout  Duration               `json:"upstream_timeout,omitempty"`   // default 60s
	ServerTimeout    Duration               `json:"server_timeout,omitempty"`     // default 10s
	AllowNonLoopback bool                   `json:"allow_non_loopback,omitempty"` // e.g. a gateway host on a network only agents reach
	// RelayProvenza passes /_provenza/api/v1/... to server_url, so an agent whose
	// network reaches only this proxy still reaches Provenza (relay.go)
	RelayProvenza bool `json:"relay_provenza,omitempty"`
	// StateDir keeps the proxy's own signing key, its receipt log and the last
	// signed policy it verified (default /var/lib/provenza-proxy)
	StateDir string `json:"state_dir,omitempty"`
	// SigningKeyFile: the proxy's signing key from a file made with
	// "provenza-proxy -genkey" (e.g. a mounted Kubernetes Secret) instead of
	// the one generated in state_dir. It must stay the same: the server keeps
	// the first key a proxy registers. The encryption key credentials are
	// sealed to is derived from it (sealed.go), so it covers both.
	SigningKeyFile string `json:"signing_key_file,omitempty"`
	// Policy: judging requests by the signed policy release itself (enforce.go)
	Policy PolicyConfig `json:"policy,omitempty"`
}

// PolicyConfig: the signed policy (docs/pvp/edge.md, sections 3-4).
type PolicyConfig struct {
	// Mode "off" (default): the server's check decides, as before; receipts
	// say no signed policy was applied. "enforce": a request goes out only if
	// the signed policy this proxy verified itself allows it too.
	Mode string `json:"mode,omitempty"`
	// Pin: the SHA-256 of a release's key manifest you trust (Policies ->
	// Signed policy), or "tofu" to trust the first release the server shows
	Pin string `json:"pin,omitempty"`
	// RequireAgentSignature: refuse requests that do not carry the agent's own
	// signed request (X-Provenza-Request) - mediated requests and bare check ids
	RequireAgentSignature bool `json:"require_agent_signature,omitempty"`
}

// Duration reads "30s", "2m" from JSON.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

// LoadConfig reads and checks a configuration file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // a typo in a security setting must not be silently ignored
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	c.SHA256 = hex.EncodeToString(sum[:])
	return &c, c.normalize()
}

func (c *Config) normalize() error {
	if !strings.HasPrefix(c.ServerURL, "https://") && !strings.HasPrefix(c.ServerURL, "http://") {
		return fmt.Errorf("server_url must start with https://")
	}
	c.ServerURL = strings.TrimRight(c.ServerURL, "/")
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8443"
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if ip := net.ParseIP(host); (ip == nil || !ip.IsLoopback()) && host != "localhost" && !c.AllowNonLoopback {
		return fmt.Errorf("listen %s is not loopback: any process that reaches it could use the credentials; "+
			"set allow_non_loopback only where the network is restricted to the agent (a pod's sidecar)", c.Listen)
	}
	if c.UpstreamTimeout.Duration == 0 {
		c.UpstreamTimeout.Duration = 60 * time.Second
	}
	if c.ServerTimeout.Duration == 0 {
		c.ServerTimeout.Duration = 10 * time.Second
	}
	if c.ProxyKeyEnv == "" {
		c.ProxyKeyEnv = "PROVENZA_PROXY_KEY"
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/provenza-proxy"
	}
	for name, s := range c.LocalSecrets {
		if s.Upstream != "" && origin(s.Upstream) == "" {
			return fmt.Errorf("local_secrets.%s.upstream: an http(s) origin, like https://api.example.com", name)
		}
	}
	switch c.Policy.Mode {
	case "", "off":
		c.Policy.Mode = "off"
	case "enforce":
		if c.Policy.Pin != "tofu" && !isHex64(c.Policy.Pin) {
			return fmt.Errorf("policy.pin: the SHA-256 of a key manifest you trust (64 hex digits), or \"tofu\"")
		}
	default:
		return fmt.Errorf("policy.mode: \"off\" or \"enforce\"")
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// ProxyKey is the proxy's own key (from the file, else the environment).
func (c *Config) ProxyKey() (string, error) {
	if c.ProxyKeyFile != "" {
		raw, err := os.ReadFile(c.ProxyKeyFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	if k := strings.TrimSpace(os.Getenv(c.ProxyKeyEnv)); k != "" {
		return k, nil
	}
	return "", fmt.Errorf("no proxy key: set %s or proxy_key_file", c.ProxyKeyEnv)
}

// localSecret resolves a local credential for a request to target (read every
// time: a rotated file takes effect at once).
func (c *Config) localSecret(name, defaultHeader, target string) (header, value string, err error) {
	s, ok := c.LocalSecrets[name]
	if !ok {
		return "", "", fmt.Errorf("%s takes a local credential, but local_secrets has none for it", name)
	}
	if s.Upstream != "" && origin(s.Upstream) != origin(target) {
		return "", "", fmt.Errorf("%s: its local credential goes only to %s, not to %s", name, s.Upstream, origin(target))
	}
	header = s.Header
	if header == "" {
		header = defaultHeader
	}
	switch {
	case s.ValueFile != "":
		raw, err := os.ReadFile(s.ValueFile)
		if err != nil {
			return "", "", err
		}
		value = strings.TrimSpace(string(raw))
	case s.ValueEnv != "":
		value = os.Getenv(s.ValueEnv)
	}
	if value == "" {
		return "", "", fmt.Errorf("%s: the local credential is empty", name)
	}
	return header, value, nil
}
