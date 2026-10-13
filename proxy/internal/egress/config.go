// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
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
}

// Config of the proxy (JSON: the standard library has no YAML).
type Config struct {
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
	return nil
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

// localSecret resolves a local credential (read every time: a rotated file takes effect at once).
func (c *Config) localSecret(slug, defaultHeader string) (header, value string, err error) {
	s, ok := c.LocalSecrets[slug]
	if !ok {
		return "", "", fmt.Errorf("route %s takes a local credential, but local_secrets has none for it", slug)
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
		return "", "", fmt.Errorf("route %s: the local credential is empty", slug)
	}
	return header, value, nil
}
