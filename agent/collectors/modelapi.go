package collectors

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// What answers on a local model port: the port being open says little (3000,
// 5000, 8000 and 8080 are every web developer's ports too), so the agent asks
// the model API that belongs there. Only the loopback, only fixed read-only
// paths, no redirects, no proxy, no credentials, a small answer: the names of
// the models are all that is kept.

const (
	modelAPITimeout = 1500 * time.Millisecond
	modelAPIMaxBody = 256 << 10 // bytes read of an answer, at most
	maxModelNames   = 20
	maxModelName    = 128
)

// modelProbe: one way to ask a server what it is.
type modelProbe struct {
	Path  string
	API   string                             // what a match means, e.g. "Ollama"
	Parse func(body []byte) ([]string, bool) // the model names, and whether the answer has this API's shape
}

// The probes per port, in order: the API that belongs to the port first, then
// the OpenAI-compatible list most local servers answer.
var (
	probeOllama = modelProbe{Path: "/api/tags", API: "Ollama", Parse: parseOllamaTags}
	probeOpenAI = modelProbe{Path: "/v1/models", API: "OpenAI-compatible", Parse: parseOpenAIModels}
	probeWebUI  = modelProbe{Path: "/api/config", API: "Open WebUI", Parse: parseOpenWebUIConfig}

	modelProbes = map[int][]modelProbe{
		11434: {probeOllama, probeOpenAI},
		1234:  {probeOpenAI},
		8080:  {probeOpenAI},
		8000:  {probeOpenAI},
		5000:  {probeOpenAI},
		3000:  {probeWebUI, probeOpenAI},
	}
)

// modelAPIResult: what the port's server turned out to be.
type modelAPIResult struct {
	Confirmed bool     // a model API answered in its own shape
	API       string   // which one
	Models    []string // its model names (cleaned, at most maxModelNames)
}

var modelHTTP = &http.Client{
	Timeout: modelAPITimeout,
	Transport: &http.Transport{
		Proxy:             nil, // never through a proxy: the question is about this machine
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// probeModelAPI asks the server at base (http://127.0.0.1:<port>) the port's questions.
func probeModelAPI(base string, port int) modelAPIResult {
	for _, p := range modelProbes[port] {
		body, err := getSmall(base + p.Path)
		if err != nil {
			continue
		}
		if models, ok := p.Parse(body); ok {
			return modelAPIResult{Confirmed: true, API: p.API, Models: cleanModelNames(models)}
		}
	}
	return modelAPIResult{}
}

func getSmall(url string) ([]byte, error) {
	resp, err := modelHTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, modelAPIMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > modelAPIMaxBody {
		return nil, errors.New("answer too large")
	}
	return body, nil
}

// Ollama: {"models": [{"name": "llama3:8b", ...}]}
func parseOllamaTags(body []byte) ([]string, bool) {
	var v struct {
		Models *[]struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if json.Unmarshal(body, &v) != nil || v.Models == nil {
		return nil, false
	}
	var out []string
	for _, m := range *v.Models {
		if m.Name != "" {
			out = append(out, m.Name)
		} else if m.Model != "" {
			out = append(out, m.Model)
		}
	}
	return out, true
}

// OpenAI-compatible (LM Studio, llama.cpp, vLLM, LocalAI, Ollama):
// {"object": "list", "data": [{"id": "...", "object": "model"}]}
func parseOpenAIModels(body []byte) ([]string, bool) {
	var v struct {
		Object string `json:"object"`
		Data   *[]struct {
			ID     string `json:"id"`
			Object string `json:"object"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &v) != nil || v.Data == nil || v.Object != "list" {
		return nil, false
	}
	var out []string
	for _, m := range *v.Data {
		if m.ID != "" && (m.Object == "" || m.Object == "model") {
			out = append(out, m.ID)
		}
	}
	return out, true
}

// Open WebUI: {"status": true, "name": "Open WebUI", "version": "..."}
func parseOpenWebUIConfig(body []byte) ([]string, bool) {
	var v struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &v) != nil {
		return nil, false
	}
	return nil, strings.Contains(strings.ToLower(v.Name), "open webui")
}

// A model name as it may be shown: printable, without anything that could be
// markup or a control sequence; what does not fit is left out.
var modelNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)

func cleanModelNames(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range in {
		n = strings.TrimSpace(n)
		if len(n) > maxModelName || !modelNameOK.MatchString(n) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) > maxModelNames {
		out = out[:maxModelNames]
	}
	return out
}
