package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AgentConfig holds runtime configuration for the endpoint collector.
type AgentConfig struct {
	APIURL       string `json:"api_url"`
	IngestionKey string `json:"ingestion_key"`
	// IngestionKeyFile: the key from a file (mode 600) instead of the
	// configuration itself - what the installer writes (deploy/edge)
	IngestionKeyFile     string   `json:"ingestion_key_file"`
	AgentID              string   `json:"agent_id"`
	ScanIntervalSec      int      `json:"scan_interval_sec"`
	BatchIntervalSec     int      `json:"batch_interval_sec"`
	BatchSize            int      `json:"batch_size"`
	ModelSearchPaths     []string `json:"model_search_paths"`
	DiscoveryEnabled     bool     `json:"discovery_enabled"`
	DiscoveryIntervalSec int      `json:"discovery_interval_sec"`
	// HeartbeatSec: how often the agent says it is alive, so its device is
	// listed even when nothing AI-related runs on it (0: the default)
	HeartbeatSec int `json:"heartbeat_sec"`
}

// GenerateRandomID creates a random hex identifier.
func GenerateRandomID(bytesLen int) string {
	b := make([]byte, bytesLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LoadConfig reads config from a JSON file and applies environment overrides.
func LoadConfig(configPath string) (*AgentConfig, error) {
	hostname, _ := os.Hostname()
	cfg := &AgentConfig{
		APIURL:               "http://localhost:8000/api/v1/shadow_ai/ingest",
		IngestionKey:         "default-key",
		AgentID:              hostname,
		ScanIntervalSec:      30,
		BatchIntervalSec:     10,
		BatchSize:            50,
		ModelSearchPaths:     []string{},
		DiscoveryEnabled:     false,
		DiscoveryIntervalSec: 900,
	}

	if data, err := os.ReadFile(configPath); err == nil {
		_ = json.Unmarshal(data, cfg)
	}

	if envURL := os.Getenv("AGENT_API_URL"); envURL != "" {
		cfg.APIURL = envURL
	}
	if cfg.IngestionKeyFile != "" {
		raw, err := os.ReadFile(cfg.IngestionKeyFile)
		if err != nil {
			return nil, fmt.Errorf("ingestion_key_file: %w", err)
		}
		cfg.IngestionKey = strings.TrimSpace(string(raw))
	}
	if envKey := os.Getenv("AGENT_INGESTION_KEY"); envKey != "" {
		cfg.IngestionKey = envKey
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 900
	}
	if os.Getenv("AGENT_DISCOVERY") == "true" {
		cfg.DiscoveryEnabled = true
	}
	if envID := os.Getenv("AGENT_ID"); envID != "" {
		cfg.AgentID = envID
	}
	if cfg.AgentID == "" {
		cfg.AgentID = hostname
	}

	// Expand ~ in search paths
	homeDir, _ := os.UserHomeDir()
	for i, path := range cfg.ModelSearchPaths {
		if strings.HasPrefix(path, "~/") {
			cfg.ModelSearchPaths[i] = strings.Replace(path, "~", homeDir, 1)
		}
	}

	return cfg, nil
}

// SearchRoots: the model search paths as they are now - a path with a
// wildcard ("/home/*/.ollama/models") is expanded on every scan, so a user
// added later is covered too.
func (c *AgentConfig) SearchRoots() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range c.ModelSearchPaths {
		matches := []string{p}
		if strings.ContainsAny(p, "*?[") {
			matches, _ = filepath.Glob(p)
		}
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}
