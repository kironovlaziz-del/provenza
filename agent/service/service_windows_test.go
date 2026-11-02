package service

import (
	"strings"
	"testing"

	"shadow-ai-agent/config"
)

func TestServiceArgs(t *testing.T) {
	p := config.InstallPaths("windows")
	a := ServiceArgs(p)
	if a[0] != "run" || a[2] != p.Config || !strings.HasSuffix(a[4], `\state\agent.log`) {
		t.Fatal(a)
	}
}
