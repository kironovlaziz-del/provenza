package service

import (
	"os"
	"path/filepath"
	"testing"

	"shadow-ai-agent/config"
)

func TestIngestURL(t *testing.T) {
	ok := map[string]string{
		"https://provenza.example.com":                  "https://provenza.example.com/api/v1/shadow-ai/ingest",
		"provenza.example.com/":                         "https://provenza.example.com/api/v1/shadow-ai/ingest",
		"https://p.example.com:8443/base":               "https://p.example.com:8443/base/api/v1/shadow-ai/ingest",
		"https://p.example.com/api/v1/shadow-ai/ingest": "https://p.example.com/api/v1/shadow-ai/ingest",
		"http://localhost:8000":                         "http://localhost:8000/api/v1/shadow-ai/ingest",
		"https://p.example.com/?x=1#f":                  "https://p.example.com/api/v1/shadow-ai/ingest",
	}
	for in, want := range ok {
		if got, err := IngestURL(in); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "http://provenza.example.com", "ftp://x", "https://"} {
		if got, err := IngestURL(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

// The configuration install writes is one the agent loads, with the key
// from the key file.
func TestRenderedConfigLoads(t *testing.T) {
	d := t.TempDir()
	p := config.Paths{Config: filepath.Join(d, "config.json"), KeyFile: filepath.Join(d, "ingestion.key"), StateDir: filepath.Join(d, "state")}
	data, err := RenderConfig(p, "https://p.example.com/api/v1/shadow-ai/ingest", Options{AgentID: "LAPTOP-7", Discovery: true})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p.Config, data, 0o600)
	os.WriteFile(p.KeyFile, []byte("ing_secret\n"), 0o600)
	c, err := config.LoadConfig(p.Config)
	if err != nil || c.IngestionKey != "ing_secret" || c.AgentID != "LAPTOP-7" || !c.DiscoveryEnabled ||
		c.StateDir != p.StateDir || len(c.ModelSearchPaths) == 0 {
		t.Fatalf("%v %+v", err, c)
	}
}
