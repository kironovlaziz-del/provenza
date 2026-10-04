package collectors

import (
	"strings"
	"testing"
)

func products(ms []Match) string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Signature.Product+"/"+m.By)
	}
	return strings.Join(out, ",")
}

func TestMatchProcess(t *testing.T) {
	cases := []struct {
		name string
		comm string
		argv []string
		want string
	}{
		{"claude code via node package", "node", []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js", "--resume"}, "claude_code/package"},
		{"claude code process title", "claude", []string{"claude"}, "claude_code/executable"},
		{"codex npx", "node", []string{"node", "/home/u/.npm/_npx/1/node_modules/@openai/codex/bin/codex.js"}, "codex_cli/executable"},
		{"aider script", "python3", []string{"/usr/bin/python3.12", "/home/u/.local/bin/aider", "--model", "x"}, "aider/executable"},
		{"aider module", "python", []string{"python", "-m", "aider.main"}, "aider/module"},
		{"crewai cli", "crewai", []string{"/venv/bin/crewai", "run"}, "crewai/executable"},
		{"copilot ls truncated comm", "copilot-languag", []string{"node", "/x/node_modules/@github/copilot-language-server/dist/language-server.js", "--stdio"}, "github_copilot/package"},
		{"cursor app", "cursor", []string{"/opt/Cursor/cursor", "--no-sandbox"}, "cursor/executable"},
		{"windows exe", "Windsurf.exe", []string{`C:\Program Files\Windsurf\Windsurf.exe`}, "windsurf/executable"},
		{"ollama runtime", "ollama", []string{"/usr/local/bin/ollama", "serve"}, "ollama/executable"},
		{"vllm module", "python3", []string{"python3", "-m", "vllm.entrypoints.openai.api_server"}, "vllm/module"},
		{"tgwebui path", "python", []string{"python", "/srv/text-generation-webui/server.py"}, "text-generation-webui/path"},
		{"npx scoped package", "node", []string{"npx", "-y", "@anthropic-ai/claude-code"}, "claude_code/executable"},
		{"uv run", "uv", []string{"uv", "run", "crewai", "run"}, "crewai/executable"},
		{"pipx run", "pipx", []string{"pipx", "run", "aider-chat"}, ""},
		{"python -X option", "python3", []string{"python3", "-X", "dev", "-m", "langflow", "run"}, "langflow/module"},
		{"goose desktop server", "goosed", []string{"/opt/Goose/goosed", "agent"}, "goose/executable"},
		{"tabby server", "tabby", []string{"tabby", "serve", "--model", "StarCoder-1B"}, "tabby/executable"},
	}
	for _, c := range cases {
		if got := products(MatchProcess(c.comm, c.argv)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// Substrings of unrelated text must not match: the old collector matched
// "jan" inside "january" and "tabby" inside any path that contained it.
func TestNoSubstringFalsePositives(t *testing.T) {
	cases := [][]string{
		{"vim", "notes-january.txt"},
		{"bash", "-c", "grep -r claude-code ~/docs"},
		{"python3", "/home/u/projects/my-ollama-notes/report.py"},
		{"node", "/srv/app/server.js", "--title", "cursor"},
		{"less", "/var/log/aider.log"},
		{"python3", "-c", "import crewai"},
		{"goose", "up"}, // pressly/goose database migrations
		{"tabby"},       // Tabby the terminal emulator
		{"vim", "/usr/lib/node_modules/n8n/package.json"},
		{"grep", "-r", "x", "/usr/lib/node_modules/@anthropic-ai/claude-code/"},
		{"interpreter"},
	}
	for _, argv := range cases {
		if got := MatchProcess(argv[0], argv); len(got) != 0 {
			t.Errorf("%v: unexpected match %s", argv, products(got))
		}
	}
}

func TestMatchCarriesNoArguments(t *testing.T) {
	ms := MatchProcess("node", []string{"node", "/n/node_modules/@anthropic-ai/claude-code/cli.js", "--api-key", "sk-ant-secret"})
	if len(ms) != 1 {
		t.Fatalf("want one match, got %d", len(ms))
	}
	if strings.Contains(ms[0].By+ms[0].Signature.Product, "sk-ant") {
		t.Fatal("argument leaked into the match")
	}
}
