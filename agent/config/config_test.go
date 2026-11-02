package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyFileAndRoots(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "home/a/m"), 0o755)
	os.MkdirAll(filepath.Join(d, "home/b/m"), 0o755)
	os.WriteFile(filepath.Join(d, "k"), []byte("secret\n"), 0o600)
	cfgp := filepath.Join(d, "c.json")
	raw, _ := json.Marshal(map[string]interface{}{ // json.Marshal: Windows paths have backslashes
		"ingestion_key_file": filepath.Join(d, "k"),
		"model_search_paths": []string{filepath.Join(d, "home", "*", "m"), "/nope"},
	})
	os.WriteFile(cfgp, raw, 0o600)
	c, err := LoadConfig(cfgp)
	if err != nil || c.IngestionKey != "secret" || c.HeartbeatSec != 900 {
		t.Fatal(err, c)
	}
	r := c.SearchRoots()
	if len(r) != 3 || r[0] != "/nope" {
		t.Fatal(r)
	}
}

func TestDefaultModelPaths(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "c.json")
	os.WriteFile(p, []byte(`{"api_url":"https://x/api/v1/shadow-ai/ingest"}`), 0o600)
	c, _ := LoadConfig(p)
	if len(c.ModelSearchPaths) == 0 || c.QueueMaxMB != 50 || c.BatchSize != 50 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	os.WriteFile(p, []byte(`{"model_search_paths":[]}`), 0o600)
	if c, _ := LoadConfig(p); len(c.ModelSearchPaths) != 0 {
		t.Fatal("[] must turn the model scan off")
	}
	t.Setenv("SystemDrive", "D:")
	if w := DefaultModelSearchPaths("windows"); w[0] != `D:\Users\*\.ollama\models` {
		t.Fatal(w)
	}
	if m := DefaultModelSearchPaths("darwin"); m[0] != "/Users/*/.ollama/models" {
		t.Fatal(m)
	}
	t.Setenv("ProgramData", `E:\PD`)
	if w := InstallPaths("windows"); w.KeyFile != `E:\PD\Provenza\Agent\ingestion.key` {
		t.Fatal(w)
	}
}
