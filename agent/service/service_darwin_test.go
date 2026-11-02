package service

import (
	"encoding/xml"
	"strings"
	"testing"

	"shadow-ai-agent/config"
)

func TestPlistIsWellFormed(t *testing.T) {
	p := config.InstallPaths("darwin")
	s := Plist(p)
	d := xml.NewDecoder(strings.NewReader(s))
	d.Strict = true
	for {
		if _, err := d.Token(); err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatal(err)
		}
	}
	for _, want := range []string{"<string>com.provenza.agent</string>", "<string>" + p.Config + "</string>", "<string>run</string>"} {
		if !strings.Contains(s, want) {
			t.Errorf("plist lacks %s", want)
		}
	}
}
