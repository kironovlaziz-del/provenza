//go:build windows

package collectors

import (
	"os"
	"strings"
	"testing"
)

// The loaded modules of this very process: the real Toolhelp call.
func TestLoadedModulesOfThisProcess(t *testing.T) {
	mods := loadedModules(os.Getpid())
	if len(mods) == 0 {
		t.Fatal("no modules for the test's own process")
	}
	found := false
	for _, m := range mods {
		if strings.HasSuffix(strings.ToLower(m), `\ntdll.dll`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("ntdll.dll is not among %d modules, e.g. %v", len(mods), mods[:min(3, len(mods))])
	}
	// and nothing for a process that does not exist
	if got := loadedModules(0x7ffffff0); len(got) != 0 {
		t.Fatalf("modules of a pid that does not exist: %v", got)
	}
}

// A probe built without any API address still reads the modules of a likely agent.
func TestWindowsProbeReadsModulesOfInterpreters(t *testing.T) {
	p := newBehaviorProbe(nil)
	_ = p.inspect(procInfo{PID: os.Getpid(), Comm: "python.exe"}, true) // must not panic or hang
}
