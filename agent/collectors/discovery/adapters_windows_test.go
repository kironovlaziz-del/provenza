//go:build windows

package discovery

import "testing"

// The real settings of the machine the test runs on: the call works and
// reports what the machine has (a CI runner has at least one adapter that is up).
func TestAdaptersOfThisMachine(t *testing.T) {
	as := adapters()
	if len(as) == 0 {
		t.Fatal("no network adapters")
	}
	up := 0
	for _, a := range as {
		if a.Up && !a.Loopback {
			up++
		}
		if a.Name == "" {
			t.Errorf("an adapter without a name: %+v", a)
		}
	}
	if up == 0 {
		t.Fatalf("no adapter is up among %d", len(as))
	}
	t.Logf("%d adapters, %d up; DNS %v; suffixes %v", len(as), up, dnsFromAdapters(as), suffixesFromAdapters(as))
	if ip, name, _ := defaultGateway(); ip == nil {
		t.Logf("no default gateway on this machine")
	} else {
		t.Logf("default gateway %v on %q", ip, name)
	}
}
