// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// Agent mode (docs/pvp/edge.md, section 4): the same binary runs next to an
// agent as a local adapter that signs with the agent's key, for clients that
// cannot sign - stock OpenAI, MCP and A2A clients, plain HTTP for egress
// routes. It signs each request it receives (X-Provenza-Request over route,
// method, path and the hashes of the query and the body, as the SDKs do) and
// passes it to the egress proxy with the agent's key; the answer comes back
// as the proxy sent it, streamed.
//
//	provenza-proxy -agent-identity ~/.config/provenza/agents/bot.json \
//	    -listen unix:/run/provenza/bot.sock -upstream http://egress-proxy:8443
//
// The identity is the agent's identity file (provenza-agent.json, saved at
// enrollment by the interface or the SDK): agent_id, api_key, the Ed25519
// private key and, for a hybrid key, the ML-DSA-65 one; the file must be
// readable by its owner only. Whoever can reach the listener acts as the
// agent: a unix socket (mode 0600: its owner only) is the way to keep it to
// the agent; a TCP address is taken on the loopback only, where any local
// process reaches it. `provenza-proxy connect` sets this up for a client
// (connect.go).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// agentBodyLimit: the largest request agent mode signs (an egress route may allow large bodies).
const agentBodyLimit = 32 << 20

// AgentIdentity: what agent mode signs with (the SDK's identity file).
type AgentIdentity struct {
	AgentID    int64  `json:"agent_id"`
	APIKey     string `json:"api_key"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	PQPrivate  string `json:"pq_private_key"`
	PQPublic   string `json:"pq_public_key"`
	Server     string `json:"server"`
	Secrets    string `json:"secrets"`
	key        ed25519.PrivateKey
	pqKey      *mldsa.PrivateKey // a hybrid key: ML-DSA-65 as well
}

// LoadAgentIdentity reads the SDK's identity file.
func LoadAgentIdentity(path string) (*AgentIdentity, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users; chmod 600 it (it holds the agent's private key)", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var id AgentIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("%s is not an identity file: %w", path, err)
	}
	switch {
	case id.Secrets == "keychain":
		return nil, errors.New("the identity keeps its secrets in the OS keychain: save it with key_store='file' for agent mode")
	case id.AgentID < 1 || id.APIKey == "":
		return nil, errors.New("the identity has no agent_id or api_key: enroll the agent first")
	}
	seed, err := base64.StdEncoding.DecodeString(id.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the identity's private_key is not a base64 Ed25519 key")
	}
	id.key = ed25519.NewKeyFromSeed(seed)
	pub := base64.StdEncoding.EncodeToString(id.key.Public().(ed25519.PublicKey))
	if id.PublicKey != "" && id.PublicKey != pub {
		return nil, errors.New("the identity's public_key is not its private key's")
	}
	id.PublicKey = pub
	if id.PQPrivate != "" {
		pqSeed, err := base64.StdEncoding.DecodeString(id.PQPrivate)
		if err != nil {
			return nil, errors.New("the identity's pq_private_key is not base64")
		}
		sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), pqSeed)
		if err != nil {
			return nil, fmt.Errorf("the identity's pq_private_key is not an ML-DSA-65 key: %w", err)
		}
		pqPub := base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes())
		if id.PQPublic != "" && id.PQPublic != pqPub {
			return nil, errors.New("the identity's pq_public_key is not its pq_private_key's")
		}
		id.pqKey, id.PQPublic = sk, pqPub
	} else if id.PQPublic != "" {
		return nil, errors.New("the identity has a pq_public_key without its pq_private_key")
	}
	return &id, nil
}

// Hybrid: the agent's key is Ed25519 + ML-DSA-65.
func (id *AgentIdentity) Hybrid() bool { return id.pqKey != nil }

// Sign: the agent's signed request (X-Provenza-Request) for d.
func (id *AgentIdentity) Sign(d Descriptor, chainID *int64, now time.Time) (string, error) {
	dmap, err := canon.Of(d)
	if err != nil {
		return "", err
	}
	sha, err := canon.SHA256(dmap)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	var chain any
	if chainID != nil {
		chain = *chainID
	}
	// docs/pvp/spec.md 3.1: what the server and the proxy verify (PVPActionRequest.signed_payload)
	payload := map[string]any{"type": "action.request", "agent_id": id.AgentID, "chain_id": chain,
		"action_type": "proxy", "tool_name": "proxy." + d.Route, "input_sha256": sha, "tool_version": nil,
		"tool_digest": nil, "nonce": hex.EncodeToString(nonce), "issued_at": now.Unix()}
	msg, err := canon.Bytes(payload)
	if err != nil {
		return "", err
	}
	signed := map[string]any{"payload": payload, "public_key": id.PublicKey,
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(id.key, msg))}
	if id.pqKey != nil {
		// both halves over the same canonical payload, as the SDKs sign (AND: the server checks both)
		pq, err := id.pqKey.Sign(nil, msg, nil)
		if err != nil {
			return "", err
		}
		signed["pq_signature"] = base64.StdEncoding.EncodeToString(pq)
		signed["pq_public_key"] = id.PQPublic
	}
	out, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// AgentListener: the socket agent mode listens on - "unix:<path>" (created
// with mode 0600; a stale socket at the path is replaced) or a loopback TCP
// address.
func AgentListener(listen string) (net.Listener, error) {
	path, isUnix := strings.CutPrefix(listen, "unix:")
	if !isUnix {
		if !loopback(listen) {
			return nil, fmt.Errorf("agent mode listens on a unix socket or the loopback only (whoever reaches it acts "+
				"as the agent): %s", listen)
		}
		return net.Listen("tcp", listen)
	}
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("agent mode: the unix socket needs an absolute path: %q", listen)
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("agent mode: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177) // the socket is created with mode 0600: no moment where others may connect
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// loopback: an address only this host can reach.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewAgentMode: the local adapter that signs as the agent and passes each
// request to the egress proxy at upstream.
func NewAgentMode(id *AgentIdentity, listen, upstream string, logger *slog.Logger) (http.Handler, error) {
	return newAgentMode(id, listen, upstream, logger, time.Now)
}

func newAgentMode(id *AgentIdentity, listen, upstream string, logger *slog.Logger,
	now func() time.Time) (http.Handler, error) {
	if !strings.HasPrefix(listen, "unix:") && !loopback(listen) {
		return nil, fmt.Errorf("agent mode listens on a unix socket or the loopback only (whoever reaches it acts "+
			"as the agent): %s", listen)
	}
	target, err := url.Parse(upstream)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" ||
		(target.Path != "" && target.Path != "/") || target.RawQuery != "" {
		// what is signed is the path the proxy receives: the proxy's root, nothing before it
		return nil, fmt.Errorf("the egress proxy's address is not an http(s) URL of its root: %q", upstream)
	}
	target.Path = ""
	if logger == nil {
		logger = slog.Default()
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
		},
		FlushInterval: -1, // streams (SSE) pass as they come
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			logger.Warn("provenza agent mode: the egress proxy is unreachable", "err", err)
			refuse(w, http.StatusBadGateway, "provenza_proxy_unreachable", "the egress proxy is unreachable")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, agentBodyLimit+1))
		if err != nil || len(body) > agentBodyLimit {
			refuse(w, http.StatusRequestEntityTooLarge, "provenza_body_too_large", "the request is too large to sign")
			return
		}
		var chain *int64
		if c := r.Header.Get("X-Provenza-Chain-Id"); c != "" {
			n, err := strconv.ParseInt(c, 10, 64)
			if err != nil || n < 1 || n > 1<<31-1 {
				refuse(w, http.StatusBadRequest, "provenza_chain_id", "X-Provenza-Chain-Id must be a positive integer")
				return
			}
			chain = &n
		}
		d, _, _, err := describe(r, body)
		if err != nil {
			refuse(w, http.StatusBadRequest, "provenza_body", "the request cannot be described")
			return
		}
		signed, err := id.Sign(d, chain, now())
		if err != nil {
			refuse(w, http.StatusInternalServerError, "provenza_sign", "the request could not be signed")
			return
		}
		out := r.Clone(r.Context())
		out.Body, out.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
		// the agent's own key travels only in X-Agent-Key; whatever the client sent instead is dropped
		for _, h := range []string{"Authorization", "X-Agent-Key", "X-Provenza-Check-Id", requestHeader,
			descriptorHeader, proxyModeHeader} {
			out.Header.Del(h)
		}
		out.Header.Set("X-Agent-Key", id.APIKey)
		out.Header.Set(requestHeader, signed)
		rp.ServeHTTP(w, out)
	}), nil
}
