package collectors

import (
	"os"
	"strings"
	"testing"

	"shadow-ai-agent/config"
)

// The process listing of the system the test runs on (CI runs it on
// Linux, Windows and macOS) finds the test itself, with its command line
// and its owner.
func TestListProcessesFindsSelf(t *testing.T) {
	procs, err := listProcesses()
	if err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	for _, p := range procs {
		if p.PID != self {
			continue
		}
		if p.Comm == "" || len(p.Argv) == 0 || !strings.Contains(strings.ToLower(p.Argv[0]), "collectors.test") {
			t.Fatalf("self listed as %+v", p)
		}
		c := NewProcessCollector(&config.AgentConfig{}, nil)
		if u := c.processUser(p); u == "" {
			t.Fatal("no owner for the test process")
		}
		// the probe runs the system's connection listing without failing
		_ = newBehaviorProbe(map[string]string{"203.0.113.1": "api.example"}).inspect(p, true)
		return
	}
	t.Fatalf("pid %d not among %d processes", self, len(procs))
}
