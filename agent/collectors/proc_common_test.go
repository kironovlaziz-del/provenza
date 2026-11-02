package collectors

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestParseNetstat(t *testing.T) {
	out := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1044
  TCP    10.0.0.5:51234         104.18.32.47:443       ESTABLISHED     4312
  TCP    10.0.0.5:51235         104.18.32.47:443       HERGESTELLT     4313
  TCP    10.0.0.5:51236         104.18.32.47:443       TIME_WAIT       0
  TCP    10.0.0.5:51237         140.82.112.3:22        ESTABLISHED     4312
  TCP    [2001:db8::5]:51240    [2606:4700::6810:84e5]:443  ESTABLISHED  77
  TCP    [::ffff:10.0.0.5]:5    [::ffff:1.2.3.4]:443   ESTABLISHED     78
`
	got := parseNetstat(out)
	want := []pidConn{{4312, "104.18.32.47"}, {4313, "104.18.32.47"}, {77, "2606:4700::6810:84e5"}, {78, "1.2.3.4"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestParseLsof(t *testing.T) {
	out := "p501\nn10.0.0.5:50001->104.18.32.47:443\nn10.0.0.5:50002->17.1.1.1:5223\np777\nn[2001:db8::5]:50003->[2606:4700::1]:443\nn*:8080\n"
	got := parseLsof(out)
	want := []pidConn{{501, "104.18.32.47"}, {777, "2606:4700::1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestConnProbe(t *testing.T) {
	api := map[string]string{"104.18.32.47": "api.openai.com", "1.2.3.4": "api.anthropic.com"}
	p := newConnProbe([]pidConn{{10, "104.18.32.47"}, {10, "1.2.3.4"}, {10, "104.18.32.47"}, {11, "9.9.9.9"}}, api)
	s := p.inspect(procInfo{PID: 10, Env: []byte("PATH=/bin\x00OPENAI_API_KEY=sk-x\x00")}, false)
	if !reflect.DeepEqual(s.APIHosts, []string{"api.anthropic.com", "api.openai.com"}) ||
		!reflect.DeepEqual(s.EnvKeys, []string{"OPENAI_API_KEY"}) || s.confidence() != "high" {
		t.Fatalf("got %+v", s)
	}
	if s := p.inspect(procInfo{PID: 11}, true); s.found() {
		t.Fatalf("unrelated connection found: %+v", s)
	}
	// a key in the environment alone is not a finding
	if s := p.inspect(procInfo{PID: 12, Env: []byte("OPENAI_API_KEY=x\x00")}, true); s.found() {
		t.Fatalf("env alone found: %+v", s)
	}
}

func TestParseProcArgs2(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 3)
	buf = append(buf, "/usr/local/bin/node\x00\x00\x00\x00node\x00/opt/bot/agent.js\x00--fast\x00HOME=/Users/a\x00ANTHROPIC_API_KEY=k\x00\x00\x00junk"...)
	exe, argv, env := parseProcArgs2(buf)
	if exe != "/usr/local/bin/node" || !reflect.DeepEqual(argv, []string{"node", "/opt/bot/agent.js", "--fast"}) {
		t.Fatalf("exe %q argv %q", exe, argv)
	}
	if got := envKeyNames(env); !reflect.DeepEqual(got, []string{"ANTHROPIC_API_KEY"}) {
		t.Fatalf("env %q -> %v", env, got)
	}
	if exe, argv, _ := parseProcArgs2([]byte{1}); exe != "" || argv != nil {
		t.Fatal("short buffer")
	}
}

func TestOwnerFromPath(t *testing.T) {
	for path, want := range map[string]string{
		"/home/alice/.ollama/models/blobs/x":              "alice",
		"/Users/bob/.cache/huggingface/hub/m.safetensors": "bob",
		`C:\Users\carol\.lmstudio\models\m.gguf`:          "carol",
		"/root/.ollama/models/x":                          "root",
		"/Users/Shared/models/x.gguf":                     "",
		"/srv/models/x.gguf":                              "",
		"/data/home/x/m.gguf":                             "",
	} {
		if got := ownerFromPath(path); got != want {
			t.Errorf("%s: got %q, want %q", path, got, want)
		}
	}
}

func TestMacAppNames(t *testing.T) {
	// macOS and Windows executables as the process listing names them
	for comm, product := range map[string]string{"LM Studio": "lmstudio", "Cursor": "cursor", "ollama.exe": "ollama", "Jan.exe": "jan"} {
		m := MatchProcess(comm, []string{comm})
		if len(m) == 0 || m[0].Signature.Product != product {
			t.Errorf("%s: %v", comm, m)
		}
	}
}
