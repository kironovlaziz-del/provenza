package service

import (
	"os"
	"testing"
)

// The unit "provenza-agent install" writes is the one the Provenza server
// installs (deploy/scripts/edge.sh): one file, two copies kept equal.
func TestUnitMatchesDeploy(t *testing.T) {
	b, err := os.ReadFile("../../deploy/edge/provenza-agent.service")
	if err != nil {
		t.Skip("not in the repository checkout:", err)
	}
	if string(b) != Unit {
		t.Fatal("service.Unit and deploy/edge/provenza-agent.service differ: change both")
	}
}
