package collectors

import (
	"path"
	"strings"
)

// Signature recognizes one AI product from a running process.
//
// Matching is by whole tokens, never by substring of the command line:
//   - Executables: the process name (comm), the basename of argv[0], and -
//     when argv[0] is an interpreter (node, python, bun, ...) - the basename
//     of the script it runs. ".exe", ".js", ".py" etc. are stripped.
//   - Packages: a Node package path in the script an interpreter runs
//     (".../node_modules/@anthropic-ai/claude-code/...").
//   - Modules: a Python module started with "-m" ("python -m aider").
//   - PathSegments: a directory in the script an interpreter runs (rare;
//     for tools that run as "python server.py" inside their checkout).
//
// Package and path checks look only at the script an interpreter runs, so
// "vim .../node_modules/n8n/package.json" or a grep through a package
// directory is not a detection.
//
// Only the product id and how it matched leave the machine - never the
// command line, which can carry API keys and tokens.
type Signature struct {
	Product     string // stable id, also the backend catalog key
	Kind        string // "agent" or "runtime"
	Risk        float64
	Executables []string
	// WithArg: an Executables match counts only if this argument is present
	// too - for names other software shares ("tabby" the terminal vs
	// "tabby serve" the model server).
	WithArg      string
	Packages     []string
	Modules      []string
	PathSegments []string
}

// Signatures is the built-in catalog. Agent ids must match the backend
// catalog in backend/app/services/agent_catalog.py.
var Signatures = []Signature{
	// ---- AI agents: software that acts on its own (edits files, runs
	// commands, calls tools), as opposed to a model runtime.
	{Product: "claude_code", Kind: "agent", Risk: 0.7, Executables: []string{"claude", "claude-code"}, Packages: []string{"@anthropic-ai/claude-code"}},
	{Product: "codex_cli", Kind: "agent", Risk: 0.7, Executables: []string{"codex"}, Packages: []string{"@openai/codex"}},
	{Product: "gemini_cli", Kind: "agent", Risk: 0.7, Executables: []string{"gemini", "gemini-cli"}, Packages: []string{"@google/gemini-cli"}},
	{Product: "github_copilot", Kind: "agent", Risk: 0.5, Executables: []string{"copilot-language-server", "copilot"}, Packages: []string{"@github/copilot-language-server", "@github/copilot"}},
	{Product: "cursor", Kind: "agent", Risk: 0.6, Executables: []string{"cursor", "cursor-agent"}},
	{Product: "windsurf", Kind: "agent", Risk: 0.6, Executables: []string{"windsurf"}},
	{Product: "aider", Kind: "agent", Risk: 0.7, Executables: []string{"aider"}, Modules: []string{"aider"}},
	// "goose" alone is also a popular database-migration tool: only goosed
	// (the agent's server, run by Goose Desktop and "goose web") counts.
	{Product: "goose", Kind: "agent", Risk: 0.7, Executables: []string{"goosed"}},
	{Product: "opencode", Kind: "agent", Risk: 0.7, Executables: []string{"opencode"}, Packages: []string{"opencode-ai"}},
	{Product: "amazon_q", Kind: "agent", Risk: 0.6, Executables: []string{"qchat", "q-chat"}},
	{Product: "openhands", Kind: "agent", Risk: 0.8, Executables: []string{"openhands"}, Modules: []string{"openhands"}},
	{Product: "open_interpreter", Kind: "agent", Risk: 0.8, Executables: []string{"open-interpreter"}, Modules: []string{"interpreter"}},
	{Product: "crewai", Kind: "agent", Risk: 0.6, Executables: []string{"crewai"}, Modules: []string{"crewai"}},
	{Product: "langgraph", Kind: "agent", Risk: 0.6, Executables: []string{"langgraph"}, Modules: []string{"langgraph_api", "langgraph_cli"}},
	{Product: "autogen_studio", Kind: "agent", Risk: 0.6, Executables: []string{"autogenstudio"}, Modules: []string{"autogenstudio"}},
	{Product: "letta", Kind: "agent", Risk: 0.6, Executables: []string{"letta"}, Modules: []string{"letta"}},
	{Product: "n8n", Kind: "agent", Risk: 0.5, Executables: []string{"n8n"}, Packages: []string{"n8n"}},
	{Product: "flowise", Kind: "agent", Risk: 0.5, Executables: []string{"flowise"}, Packages: []string{"flowise"}},
	{Product: "langflow", Kind: "agent", Risk: 0.5, Executables: []string{"langflow"}, Modules: []string{"langflow"}},

	// ---- Local model runtimes (reported as process_detected, as before).
	{Product: "ollama", Kind: "runtime", Risk: 0.6, Executables: []string{"ollama"}},
	{Product: "lmstudio", Kind: "runtime", Risk: 0.7, Executables: []string{"lmstudio", "lm-studio", "lms"}},
	{Product: "vllm", Kind: "runtime", Risk: 0.8, Executables: []string{"vllm"}, Modules: []string{"vllm"}},
	{Product: "localai", Kind: "runtime", Risk: 0.7, Executables: []string{"localai", "local-ai"}},
	{Product: "llama.cpp", Kind: "runtime", Risk: 0.6, Executables: []string{"llama-server", "llama-cli", "llama-cpp-server"}, Modules: []string{"llama_cpp"}},
	{Product: "text-generation-webui", Kind: "runtime", Risk: 0.7, PathSegments: []string{"text-generation-webui"}},
	{Product: "jan", Kind: "runtime", Risk: 0.6, Executables: []string{"jan"}},
	{Product: "anythingllm", Kind: "runtime", Risk: 0.6, Executables: []string{"anythingllm", "anything-llm"}},
	{Product: "tabby", Kind: "runtime", Risk: 0.5, Executables: []string{"tabby"}, WithArg: "serve"},
	{Product: "litellm", Kind: "runtime", Risk: 0.5, Executables: []string{"litellm"}, Modules: []string{"litellm"}},
}

var interpreters = map[string]bool{
	"node": true, "nodejs": true, "bun": true, "deno": true,
	"python": true, "pypy3": true,
	"uv": true, "uvx": true, "pipx": true, "npx": true,
}

var strippedExt = []string{".exe", ".js", ".mjs", ".cjs", ".py", ".sh", ".cmd", ".appimage"}

func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = path.Base(strings.ReplaceAll(s, "\\", "/"))
	for _, ext := range strippedExt {
		s = strings.TrimSuffix(s, ext)
	}
	return s
}

// interpreterName folds versioned interpreters: python3.12 -> python.
func interpreterName(s string) string {
	n := normalizeName(s)
	if strings.HasPrefix(n, "python") {
		return "python"
	}
	return n
}

// Match is what a process matched, without any of its arguments.
type Match struct {
	Signature *Signature
	By        string // "executable", "package", "module" or "path"
}

// Launcher subcommands that come before the tool itself: "uv run crewai",
// "pipx run aider", "npx -y @openai/codex", "npm exec ...".
var launcherWords = map[string]bool{"run": true, "exec": true, "x": true, "tool": true, "--": true}

// Python options that take a value: "python -X dev app.py".
var optionsWithValue = map[string]bool{"-X": true, "-W": true, "--from": true, "--with": true, "-p": true, "--package": true}

// MatchProcess returns every signature the process matches (at most one per
// product). comm is /proc/<pid>/comm; argv is the NUL-split command line.
func MatchProcess(comm string, argv []string) []Match {
	names := map[string]bool{}
	if c := normalizeName(comm); c != "" {
		names[c] = true
	}
	var modules []string
	script := ""
	if len(argv) > 0 {
		names[normalizeName(argv[0])] = true
		if interpreters[interpreterName(argv[0])] {
			for i := 1; i < len(argv); i++ {
				a := argv[i]
				if a == "-m" && i+1 < len(argv) {
					modules = append(modules, strings.ToLower(argv[i+1]))
					break
				}
				if a == "-c" {
					break // inline code, no script
				}
				if optionsWithValue[a] {
					i++
					continue
				}
				if strings.HasPrefix(a, "-") || launcherWords[strings.ToLower(a)] {
					continue
				}
				// the script or tool the interpreter runs: "node /x/cli.js" -> cli,
				// "python ~/.local/bin/aider" -> aider, "npx pkg" -> pkg
				script = a
				names[normalizeName(a)] = true
				break
			}
		}
	}

	var out []Match
	for i := range Signatures {
		s := &Signatures[i]
		if by := s.match(names, modules, script, argv); by != "" {
			out = append(out, Match{Signature: s, By: by})
		}
	}
	return out
}

func (s *Signature) match(names map[string]bool, modules []string, script string, argv []string) string {
	for _, e := range s.Executables {
		if names[e] && (s.WithArg == "" || hasArg(argv, s.WithArg)) {
			return "executable"
		}
	}
	for _, m := range s.Modules {
		for _, got := range modules {
			if got == m || strings.HasPrefix(got, m+".") {
				return "module"
			}
		}
	}
	if script == "" {
		return ""
	}
	a := strings.ToLower(strings.ReplaceAll(script, "\\", "/"))
	for _, p := range s.Packages {
		if strings.Contains(a, "node_modules/"+p+"/") || strings.HasSuffix(a, "node_modules/"+p) || a == p {
			return "package"
		}
	}
	for _, seg := range s.PathSegments {
		if strings.Contains("/"+a+"/", "/"+seg+"/") {
			return "path"
		}
	}
	return ""
}

func hasArg(argv []string, want string) bool {
	for _, a := range argv[min(1, len(argv)):] {
		if a == want {
			return true
		}
	}
	return false
}
