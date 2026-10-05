package collectors

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Two ESTABLISHED connections to :443 (one to 104.18.33.45, one IPv6), one
// to :80 and one in LISTEN state.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 2D211268:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 111 1 0 20 4 30 10 -1
   1: 0100007F:1F91 2D211268:0050 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0 20 4 30 10 -1
   2: 00000000:1F92 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 333 1 0 20 4 30 10 -1
`

func TestParseProcNetTCP(t *testing.T) {
	got := parseProcNetTCP(procNetTCP, false)
	want := map[string]string{"111": "104.18.33.45"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDecodeProcIPv6(t *testing.T) {
	// 2606:4700::6810:2d21 as /proc/net/tcp6 writes it
	ip := decodeProcIP("00470626"+"00000000"+"00000000"+"212D1068", true)
	if ip == nil || ip.String() != "2606:4700::6810:2d21" {
		t.Fatalf("got %v", ip)
	}
	if decodeProcIP("zz", false) != nil || decodeProcIP("2D211268", true) != nil {
		t.Fatal("malformed input must not decode")
	}
}

func TestEnvKeyNamesNeverCarryValues(t *testing.T) {
	env := []byte("HOME=/home/u\x00OPENAI_API_KEY=sk-secret\x00ANTHROPIC_API_KEY=sk-ant-x\x00PATH=/bin\x00")
	got := envKeyNames(env)
	if !reflect.DeepEqual(got, []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}) {
		t.Fatalf("got %v", got)
	}
	if strings.Contains(strings.Join(got, ","), "sk-") {
		t.Fatal("a value leaked")
	}
}

func TestSDKMarkers(t *testing.T) {
	maps := []byte("7f00-7f10 r-xp 0 08:01 1 /venv/lib/python3.12/site-packages/jiter/jiter.cpython-312-x86_64-linux-gnu.so\n" +
		"7f20-7f30 r-xp 0 08:01 2 /venv/lib/python3.12/site-packages/tiktoken/_tiktoken.cpython-312.so\n")
	if got := sdkMarkers(maps); !reflect.DeepEqual(got, []string{"openai-or-anthropic-python", "tiktoken"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCustomProductID(t *testing.T) {
	cases := []struct {
		comm string
		argv []string
		want string
	}{
		{"python3", []string{"/usr/bin/python3", "/srv/bots/Sales Bot.py", "--live"}, "custom.sales_bot"},
		{"python3", []string{"python3", "-m", "support_agent.main"}, "custom.support_agent"},
		{"node", []string{"node", "/app/dist/index.js"}, "custom.index"},
		{"ticket-triage", []string{"/opt/triage/ticket-triage"}, "custom.ticket-triage"},
		{"python3", []string{"python3", "-c", "print(1)"}, "custom.python3"},
	}
	for _, c := range cases {
		if got := customProductID(c.comm, c.argv); got != c.want {
			t.Errorf("%v: got %q, want %q", c.argv, got, c.want)
		}
	}
}

func TestInspectProcess(t *testing.T) {
	files := map[string]string{
		"/proc/7/environ": "OPENAI_API_KEY=sk-x\x00",
		"/proc/7/maps":    "",
	}
	links := map[string]string{"/proc/7/fd/3": "socket:[111]", "/proc/7/fd/4": "/dev/null"}
	readFile := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no")
	}
	readLink := func(p string) (string, error) {
		if v, ok := links[p]; ok {
			return v, nil
		}
		return "", errors.New("no")
	}
	list := func(string) ([]string, error) { return []string{"3", "4"}, nil }
	sockets := map[string]string{"111": "104.18.33.45"}
	apiIPs := map[string]string{"104.18.33.45": "api.openai.com"}

	s := inspectProcess(7, false, sockets, apiIPs, readFile, readLink, list)
	if !s.found() || s.confidence() != "high" || !reflect.DeepEqual(s.APIHosts, []string{"api.openai.com"}) ||
		!reflect.DeepEqual(s.EnvKeys, []string{"OPENAI_API_KEY"}) {
		t.Fatalf("got %+v (%s)", s, s.confidence())
	}

	// an API connection alone is medium: a CDN address can serve other sites
	files["/proc/7/environ"] = ""
	if s := inspectProcess(7, false, sockets, apiIPs, readFile, readLink, list); s.confidence() != "medium" {
		t.Fatalf("want medium, got %s", s.confidence())
	}

	// a key variable alone is not a finding
	files["/proc/7/environ"] = "OPENAI_API_KEY=sk-x\x00"
	if s := inspectProcess(7, true, map[string]string{}, apiIPs, readFile, readLink, list); s.found() {
		t.Fatalf("env alone must not count: %+v", s)
	}
}

func TestResolverKeepsLastGoodAnswer(t *testing.T) {
	r := newAPIResolver()
	var calls atomic.Int32 // lookups run in parallel
	r.lookup = func(h string) ([]net.IP, error) {
		calls.Add(1)
		if h == "api.openai.com" {
			return []net.IP{net.ParseIP("104.18.33.45")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	if got := r.addresses(); got["104.18.33.45"] != "api.openai.com" {
		t.Fatalf("got %v", got)
	}
	// cached within refreshEvery
	before := calls.Load()
	if got := llmSockets(map[string]string{"1": "104.18.33.45", "2": "8.8.8.8"}, r.addresses()); len(got) != 1 || got["1"] == "" {
		t.Fatalf("llmSockets kept %v", got)
	}
	r.addresses()
	if calls.Load() != before {
		t.Fatal("resolved again before refresh")
	}
	// DNS down at refresh: keep the previous addresses
	r.updated = time.Now().Add(-time.Hour)
	r.lookup = func(string) ([]net.IP, error) { return nil, errors.New("down") }
	if got := r.addresses(); got["104.18.33.45"] != "api.openai.com" {
		t.Fatalf("lost addresses on DNS failure: %v", got)
	}
}
