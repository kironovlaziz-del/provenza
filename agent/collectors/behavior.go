package collectors

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Behavioral detection of AI agents the catalog does not know: a process
// that talks to an LLM API, carries an LLM API key in its environment, or
// has an LLM SDK loaded is an AI agent or AI application, whatever it is
// called. Three signals, all read from /proc:
//
//   - api:  an established TCP connection to an address of a known LLM API
//     host (resolved periodically; addresses behind shared CDNs can also
//     serve other sites, so this alone is "medium" confidence);
//   - env:  names of LLM API key variables in the environment - only the
//     names are compared and reported, never a value;
//   - sdk:  native libraries of LLM SDKs mapped into the process
//     (jiter: OpenAI / Anthropic Python SDKs; tiktoken; tokenizers).
//
// Reading another user's /proc/<pid>/{fd,environ,maps} needs root (or
// CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH); without it only processes of the
// collector's own user are covered.

// LLMAPIHosts are resolved to addresses for the "api" signal.
var LLMAPIHosts = []string{
	"api.openai.com",
	"api.anthropic.com",
	"generativelanguage.googleapis.com",
	"api.mistral.ai",
	"api.cohere.com",
	"api.cohere.ai",
	"api.groq.com",
	"api.deepseek.com",
	"api.together.xyz",
	"api.fireworks.ai",
	"openrouter.ai",
	"api.perplexity.ai",
	"api.x.ai",
	"bedrock-runtime.us-east-1.amazonaws.com",
	"bedrock-runtime.us-west-2.amazonaws.com",
	"bedrock-runtime.eu-central-1.amazonaws.com",
	"dashscope.aliyuncs.com",
	"api.moonshot.cn",
}

// llmKeyVars are environment variable NAMES that hold LLM API credentials.
var llmKeyVars = map[string]bool{
	"OPENAI_API_KEY": true, "ANTHROPIC_API_KEY": true, "GEMINI_API_KEY": true,
	"GOOGLE_GENERATIVE_AI_API_KEY": true, "MISTRAL_API_KEY": true, "GROQ_API_KEY": true,
	"COHERE_API_KEY": true, "CO_API_KEY": true, "DEEPSEEK_API_KEY": true,
	"OPENROUTER_API_KEY": true, "AZURE_OPENAI_API_KEY": true, "TOGETHER_API_KEY": true,
	"FIREWORKS_API_KEY": true, "XAI_API_KEY": true, "PERPLEXITY_API_KEY": true,
	"DASHSCOPE_API_KEY": true, "MOONSHOT_API_KEY": true,
}

// sdkLibs: a substring of a mapped file path -> the SDK it indicates.
var sdkLibs = []struct{ marker, sdk string }{
	{"/jiter/", "openai-or-anthropic-python"},
	{"/tiktoken/", "tiktoken"},
	{"/tokenizers/", "huggingface-tokenizers"},
}

// Programs whose AI traffic is not an agent of their own: browsers (their
// users are covered by the extension and Shadow AI), and this collector.
var behaviorIgnore = map[string]bool{
	"chrome": true, "chromium": true, "chromium-browser": true, "firefox": true, "firefox-esr": true,
	"msedge": true, "microsoft-edge": true, "brave": true, "opera": true, "vivaldi": true, "safari": true,
	"shadow-agent": true, "shadow-ai-agent": true, "curl": true, "wget": true,
}

// apiResolver keeps ip -> host for LLMAPIHosts, refreshed every refreshEvery.
type apiResolver struct {
	mu           sync.Mutex
	byIP         map[string]string
	updated      time.Time
	refreshEvery time.Duration
	lookup       func(string) ([]net.IP, error)
}

// lookupTimeout bounds each DNS lookup, so a dead resolver costs the scan
// at most this long (lookups run in parallel).
const lookupTimeout = 3 * time.Second

func newAPIResolver() *apiResolver {
	return &apiResolver{byIP: map[string]string{}, refreshEvery: 10 * time.Minute, lookup: lookupIP}
}

func lookupIP(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, err
}

func (r *apiResolver) addresses() map[string]string {
	r.mu.Lock()
	if time.Since(r.updated) < r.refreshEvery && !r.updated.IsZero() {
		cached := r.byIP
		r.mu.Unlock()
		return cached
	}
	lookup := r.lookup
	r.mu.Unlock()

	// resolve without holding the lock, all hosts at once
	type answer struct {
		host string
		ips  []net.IP
	}
	ch := make(chan answer, len(LLMAPIHosts))
	for _, h := range LLMAPIHosts {
		go func(h string) {
			ips, _ := lookup(h)
			ch <- answer{h, ips}
		}(h)
	}
	fresh := map[string]string{}
	for range LLMAPIHosts {
		a := <-ch
		for _, ip := range a.ips {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			fresh[ip.String()] = a.host
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(fresh) > 0 { // DNS down: keep the last good answer
		r.byIP = fresh
	}
	r.updated = time.Now()
	return r.byIP
}

// llmSockets keeps only the HTTPS connections to LLM API addresses: when
// there are none, no process's file descriptors need to be read at all.
func llmSockets(sockets, apiIPs map[string]string) map[string]string {
	out := map[string]string{}
	for inode, ip := range sockets {
		if _, ok := apiIPs[ip]; ok {
			out[inode] = ip
		}
	}
	return out
}

// parseProcNetTCP returns socket inode -> remote IP for ESTABLISHED
// connections to port 443 in /proc/net/tcp or tcp6 content.
func parseProcNetTCP(content string, v6 bool) map[string]string {
	out := map[string]string{}
	for i, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 || f[3] != "01" { // header / short / not ESTABLISHED
			continue
		}
		hostPort := strings.SplitN(f[2], ":", 2)
		if len(hostPort) != 2 {
			continue
		}
		if port, err := strconv.ParseUint(hostPort[1], 16, 16); err != nil || port != 443 {
			continue
		}
		ip := decodeProcIP(hostPort[0], v6)
		if ip == nil {
			continue
		}
		out[f[9]] = ip.String()
	}
	return out
}

// /proc/net/tcp stores addresses as 32-bit little-endian words.
func decodeProcIP(h string, v6 bool) net.IP {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) || (len(b) == 16) != v6 {
		return nil
	}
	ip := make(net.IP, len(b))
	for w := 0; w < len(b); w += 4 {
		binary.BigEndian.PutUint32(ip[w:], binary.LittleEndian.Uint32(b[w:]))
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// envKeyNames returns the LLM key variable names set in an environ blob.
func envKeyNames(environ []byte) []string {
	var names []string
	for _, kv := range strings.Split(string(environ), "\x00") {
		name, _, ok := strings.Cut(kv, "=")
		if ok && llmKeyVars[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// sdkMarkers returns the SDKs whose native libraries appear in a maps blob.
func sdkMarkers(maps []byte) []string {
	seen := map[string]bool{}
	text := string(maps)
	for _, l := range sdkLibs {
		if strings.Contains(text, l.marker) {
			seen[l.sdk] = true
		}
	}
	var out []string
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

var unsafeID = regexp.MustCompile(`[^a-z0-9_.-]+`)

// customProductID names an unrecognized agent by what runs: the script for
// an interpreter ("python3 /srv/bots/sales_bot.py" -> custom.sales_bot),
// otherwise the executable. Stable across restarts, no arguments.
func customProductID(comm string, argv []string) string {
	name := normalizeName(comm)
	if len(argv) > 0 {
		name = normalizeName(argv[0])
		if interpreters[interpreterName(argv[0])] {
			for i := 1; i < len(argv); i++ {
				a := argv[i]
				if a == "-m" && i+1 < len(argv) {
					name = strings.SplitN(strings.ToLower(argv[i+1]), ".", 2)[0]
					break
				}
				if a == "-c" {
					break
				}
				if optionsWithValue[a] {
					i++
					continue
				}
				if strings.HasPrefix(a, "-") || launcherWords[strings.ToLower(a)] {
					continue
				}
				name = normalizeName(path.Base(a))
				break
			}
		}
	}
	id := strings.Trim(unsafeID.ReplaceAllString(name, "_"), "_.-")
	if id == "" {
		id = "process"
	}
	if len(id) > 50 {
		id = id[:50]
	}
	return "custom." + id
}

// behaviorSignals inspects one process. sockets is inode -> remote IP of
// HTTPS connections, apiIPs is ip -> LLM host. readFile is os.ReadFile (a
// parameter for tests).
type behaviorSignals struct {
	APIHosts []string
	EnvKeys  []string
	SDKs     []string
}

// found: an LLM API connection or a loaded SDK. Key variables alone do not
// count - a key exported in a shell profile reaches every process - they
// only raise the confidence of the other two.
func (s behaviorSignals) found() bool { return len(s.APIHosts)+len(s.SDKs) > 0 }

// confidence: high when two independent signals agree, or an SDK is loaded
// (a library is a direct fact; an address can be a shared CDN).
func (s behaviorSignals) confidence() string {
	n := 0
	for _, l := range [][]string{s.APIHosts, s.EnvKeys, s.SDKs} {
		if len(l) > 0 {
			n++
		}
	}
	if n >= 2 || len(s.SDKs) > 0 {
		return "high"
	}
	return "medium"
}

func inspectProcess(pid int, interpreted bool, sockets, apiIPs map[string]string,
	readFile func(string) ([]byte, error), readLink func(string) (string, error), listDir func(string) ([]string, error)) behaviorSignals {
	var s behaviorSignals

	if len(sockets) > 0 && len(apiIPs) > 0 {
		hosts := map[string]bool{}
		fds, _ := listDir(fmt.Sprintf("/proc/%d/fd", pid))
		for _, fd := range fds {
			target, err := readLink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if ip, ok := sockets[inode]; ok {
				if host, ok := apiIPs[ip]; ok {
					hosts[host] = true
				}
			}
		}
		for h := range hosts {
			s.APIHosts = append(s.APIHosts, h)
		}
		sort.Strings(s.APIHosts)
	}

	// env and maps are read only for likely agents (interpreters, or a
	// process already talking to an LLM API): cheap, and less intrusive.
	if interpreted || len(s.APIHosts) > 0 {
		if env, err := readFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
			s.EnvKeys = envKeyNames(env)
		}
		if maps, err := readFile(fmt.Sprintf("/proc/%d/maps", pid)); err == nil {
			s.SDKs = sdkMarkers(maps)
		}
	}
	return s
}

// httpsSockets reads both TCP tables of the host.
func httpsSockets() map[string]string {
	out := map[string]string{}
	for file, v6 := range map[string]bool{"/proc/net/tcp": false, "/proc/net/tcp6": true} {
		if b, err := os.ReadFile(file); err == nil {
			for k, v := range parseProcNetTCP(string(b), v6) {
				out[k] = v
			}
		}
	}
	return out
}

func listDir(dir string) ([]string, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.Readdirnames(-1)
}
