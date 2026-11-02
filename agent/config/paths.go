package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// Where the installed agent keeps its files, per operating system
// (provenza-agent install writes them; see the service package).
type Paths struct {
	Binary   string // the installed executable
	Config   string // config.json
	KeyFile  string // ingestion.key, readable by the service account only
	StateDir string // the on-disk queue of undelivered events, the log on Windows
}

// InstallPaths returns the locations for goos ("linux", "windows", "darwin").
func InstallPaths(goos string) Paths {
	switch goos {
	case "windows":
		pf := envOr("ProgramFiles", `C:\Program Files`)
		pd := envOr("ProgramData", `C:\ProgramData`)
		etc := pd + `\Provenza\Agent`
		return Paths{
			Binary:   pf + `\Provenza\provenza-agent.exe`,
			Config:   etc + `\config.json`,
			KeyFile:  etc + `\ingestion.key`,
			StateDir: etc + `\state`,
		}
	case "darwin":
		etc := "/Library/Application Support/Provenza Agent"
		return Paths{
			Binary:   "/usr/local/bin/provenza-agent",
			Config:   etc + "/config.json",
			KeyFile:  etc + "/ingestion.key",
			StateDir: etc + "/state",
		}
	default: // the same paths as deploy/scripts/edge.sh
		return Paths{
			Binary:   "/usr/local/bin/provenza-agent",
			Config:   "/etc/provenza-agent/config.json",
			KeyFile:  "/etc/provenza-agent/ingestion.key",
			StateDir: "/var/lib/provenza-agent",
		}
	}
}

// DefaultModelSearchPaths: where local model runtimes keep their models
// for every user of the machine (Ollama, Hugging Face, LM Studio, GPT4All,
// Jan). A wildcard is expanded on each scan, so a new user is covered.
func DefaultModelSearchPaths(goos string) []string {
	switch goos {
	case "windows":
		users := envOr("SystemDrive", "C:") + `\Users\*`
		return []string{
			users + `\.ollama\models`,
			users + `\.cache\huggingface\hub`,
			users + `\.cache\lm-studio\models`,
			users + `\.lmstudio\models`,
			users + `\AppData\Local\nomic.ai\GPT4All`,
			users + `\jan\models`,
			users + `\models`,
		}
	case "darwin":
		return []string{
			"/Users/*/.ollama/models",
			"/Users/*/.cache/huggingface/hub",
			"/Users/*/.cache/lm-studio/models",
			"/Users/*/.lmstudio/models",
			"/Users/*/Library/Application Support/nomic.ai/GPT4All",
			"/Users/*/jan/models",
			"/Users/*/models",
		}
	default:
		return []string{
			"/root/.ollama/models", "/home/*/.ollama/models", "/usr/share/ollama/.ollama/models",
			"/home/*/.cache/huggingface/hub", "/home/*/.cache/lm-studio/models",
			"/home/*/.lmstudio/models", "/home/*/models",
		}
	}
}

// DefaultStateDir: the installed location when it is writable, otherwise
// the user's cache directory (the agent run by hand, without install).
func DefaultStateDir() string {
	dir := InstallPaths(runtime.GOOS).StateDir
	if err := os.MkdirAll(dir, 0o700); err == nil {
		if f, err := os.CreateTemp(dir, ".probe"); err == nil {
			name := f.Name()
			f.Close()
			os.Remove(name)
			return dir
		}
	}
	if cache, err := os.UserCacheDir(); err == nil {
		return filepath.Join(cache, "provenza-agent")
	}
	return filepath.Join(os.TempDir(), "provenza-agent")
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
