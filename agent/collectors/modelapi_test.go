package collectors

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func serve(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := routes[r.URL.Path]; ok && r.Method == http.MethodGet {
			w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProbeOllama(t *testing.T) {
	srv := serve(t, map[string]string{"/api/tags": `{"models":[{"name":"llama3:8b"},{"name":"qwen2.5-coder:7b"},` +
		`{"name":"<script>alert(1)</script>"},{"name":"llama3:8b"},{"model":"phi3:mini"}]}`})
	got := probeModelAPI(srv.URL, 11434)
	want := modelAPIResult{Confirmed: true, API: "Ollama", Models: []string{"llama3:8b", "phi3:mini", "qwen2.5-coder:7b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	// an Ollama with no models is still an Ollama
	srv = serve(t, map[string]string{"/api/tags": `{"models":[]}`})
	if got := probeModelAPI(srv.URL, 11434); !got.Confirmed || len(got.Models) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestProbeOpenAICompatible(t *testing.T) {
	srv := serve(t, map[string]string{"/v1/models": `{"object":"list","data":[{"id":"TheBloke/Mistral-7B-GGUF","object":"model"},{"id":"x y","object":"model"}]}`})
	for _, port := range []int{1234, 8080, 8000, 5000, 11434} {
		got := probeModelAPI(srv.URL, port)
		if !got.Confirmed || got.API != "OpenAI-compatible" || !reflect.DeepEqual(got.Models, []string{"TheBloke/Mistral-7B-GGUF"}) {
			t.Fatalf("port %d: %+v", port, got)
		}
	}
}

func TestProbeOpenWebUI(t *testing.T) {
	srv := serve(t, map[string]string{"/api/config": `{"status":true,"name":"Open WebUI","version":"0.5.1"}`})
	if got := probeModelAPI(srv.URL, 3000); !got.Confirmed || got.API != "Open WebUI" {
		t.Fatalf("got %+v", got)
	}
}

func TestProbeSomethingElse(t *testing.T) {
	for name, routes := range map[string]map[string]string{
		"a web app":            {"/": "<html>hello</html>", "/v1/models": "<html>not json</html>"},
		"another JSON":         {"/v1/models": `{"data":[{"id":"x"}]}`, "/api/tags": `{"tags":[]}`},
		"wrong shape of data":  {"/v1/models": `{"object":"list","data":"x"}`},
		"a config of anything": {"/api/config": `{"name":"Grafana"}`},
		"nothing":              {},
	} {
		srv := serve(t, routes)
		for _, port := range []int{3000, 8080, 11434} {
			if got := probeModelAPI(srv.URL, port); got.Confirmed {
				t.Fatalf("%s on %d: %+v", name, port, got)
			}
		}
	}
	// a port that is not a model port is never asked
	srv := serve(t, map[string]string{"/v1/models": `{"object":"list","data":[]}`})
	if got := probeModelAPI(srv.URL, 22); got.Confirmed {
		t.Fatalf("asked port 22: %+v", got)
	}
}

func TestProbeDoesNotFollowRedirects(t *testing.T) {
	var hit atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.Write([]byte(`{"object":"list","data":[{"id":"m"}]}`))
	}))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.RedirectHandler(elsewhere.URL+"/v1/models", http.StatusFound))
	defer srv.Close()
	if got := probeModelAPI(srv.URL, 8080); got.Confirmed || hit.Load() {
		t.Fatalf("followed a redirect: %+v", got)
	}
}

func TestProbeRefusesALargeAnswer(t *testing.T) {
	big := `{"object":"list","data":[{"id":"m","pad":"` + strings.Repeat("x", modelAPIMaxBody) + `"}]}`
	srv := serve(t, map[string]string{"/v1/models": big})
	if got := probeModelAPI(srv.URL, 8080); got.Confirmed {
		t.Fatalf("read an answer over the limit: %+v", got)
	}
}

func TestCleanModelNames(t *testing.T) {
	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, "m"+strings.Repeat("a", i))
	}
	if got := cleanModelNames(many); len(got) != maxModelNames {
		t.Fatalf("%d names kept", len(got))
	}
	bad := []string{"", " ", "a\nb", "a\x1b[31mb", "-rf", strings.Repeat("a", maxModelName+1), "ok:1", "a b", `a"b`, "<b>"}
	if got := cleanModelNames(bad); !reflect.DeepEqual(got, []string{"ok:1"}) {
		t.Fatalf("got %q", got)
	}
}

// The collector: a confirmed API, then the same again (not reported twice), then
// a change of models (reported), then a port where nothing answers (low risk).
func TestNetworkCollectorReportsChanges(t *testing.T) {
	c := &NetworkCollector{openPorts: map[int]string{}}
	steps := []struct {
		res  modelAPIResult
		want bool
	}{
		{modelAPIResult{Confirmed: true, API: "Ollama", Models: []string{"a"}}, true},
		{modelAPIResult{Confirmed: true, API: "Ollama", Models: []string{"a"}}, false},
		{modelAPIResult{Confirmed: true, API: "Ollama", Models: []string{"a", "b"}}, true},
		{modelAPIResult{}, true},
		{modelAPIResult{}, false},
	}
	for i, s := range steps {
		if got := c.changed(11434, s.res); got != s.want {
			t.Fatalf("step %d: changed = %v", i, got)
		}
	}
}

func TestPortEvent(t *testing.T) {
	ev := portEvent(11434, "Ollama API", 0.6, modelAPIResult{Confirmed: true, API: "Ollama", Models: []string{"llama3:8b"}})
	if ev.RiskScore != 0.6 || ev.Payload["confirmed"] != true || ev.Payload["api"] != "Ollama" ||
		!reflect.DeepEqual(ev.Payload["models"], []string{"llama3:8b"}) || ev.Domain != "localhost:11434" {
		t.Fatalf("%+v", ev)
	}
	ev = portEvent(3000, "Open-WebUI", 0.5, modelAPIResult{})
	if ev.RiskScore != unconfirmedRisk || ev.Payload["confirmed"] != false || ev.Payload["models"] != nil ||
		!strings.Contains(ev.Payload["service"].(string), "no model API") {
		t.Fatalf("%+v", ev)
	}
}
