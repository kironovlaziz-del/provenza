package config

import (
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
	os.WriteFile(cfgp, []byte(`{"ingestion_key_file":"`+filepath.Join(d, "k")+`","model_search_paths":["`+d+`/home/*/m","/nope"]}`), 0o600)
	c, err := LoadConfig(cfgp)
	if err != nil || c.IngestionKey != "secret" || c.HeartbeatSec != 900 {
		t.Fatal(err, c)
	}
	r := c.SearchRoots()
	if len(r) != 3 || r[0] != "/nope" {
		t.Fatal(r)
	}
}
