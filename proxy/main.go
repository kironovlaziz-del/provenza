// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Command provenza-proxy: the Provenza egress proxy (see internal/egress).
//
//	provenza-proxy -config /etc/provenza/proxy.json
//
// Agent mode, next to an agent whose client cannot sign (internal/egress/agentmode.go):
//
//	provenza-proxy -agent-identity bot.json -listen unix:/run/provenza/bot.sock -upstream http://egress-proxy:8443
//
// An AI client connected in one command (internal/connect): agent mode as a
// service of this user, and Provenza's MCP endpoint in the client's configuration:
//
//	provenza-proxy connect gemini-cli [--identity provenza-agent.json] [--proxy http://127.0.0.1:8443]
//
// The agent enrolled on this machine with an administrator's one-time token
// (its keys made here; what Agents -> Connect runs before connect):
//
//	provenza-proxy enroll --server https://provenza.example.com --token pvz_enr_... [--name bot]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/connect"
	"github.com/kironovlaziz-del/provenza/proxy/internal/egress"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "connect" {
		os.Exit(runConnect(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		os.Exit(runEnroll(os.Args[2:]))
	}
	path := flag.String("config", "/etc/provenza/proxy.json", "configuration file (JSON)")
	genkey := flag.Bool("genkey", false, "print a new signing key (for signing_key_file; the encryption key "+
		"sealed credentials are opened with is derived from it) and exit; its fingerprint goes to stderr")
	identity := flag.String("agent-identity", "", "agent mode: the agent's identity file (the SDK's); "+
		"sign each request with its key and pass it to -upstream")
	listen := flag.String("listen", "", "agent mode: unix:<path> (mode 0600, recommended) or a loopback address "+
		"(any local process reaching it acts as the agent)")
	upstream := flag.String("upstream", "", "agent mode: the egress proxy (http(s)://host:port)")
	flag.Parse()
	if *identity != "" {
		log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		if err := runAgent(*identity, *listen, *upstream, log); err != nil {
			log.Error("provenza agent mode stopped", "err", err)
			os.Exit(1)
		}
		return
	}
	if *genkey {
		seed, fp, err := egress.NewSigningKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(seed)
		fmt.Fprintln(os.Stderr, "fingerprint:", fp)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*path, log); err != nil {
		log.Error("provenza proxy stopped", "err", err)
		os.Exit(1)
	}
}

func run(path string, log *slog.Logger) error {
	cfg, err := egress.LoadConfig(path)
	if err != nil {
		return err
	}
	key, err := cfg.ProxyKey()
	if err != nil {
		return err
	}
	if sock := os.Getenv(egress.SensorSocketEnv); sock != "" {
		// started by the egress sensor: it lets this proxy out only with a pinned configuration
		if err := egress.ReportConfig(sock, cfg.SHA256); err != nil {
			return fmt.Errorf("the egress sensor refused this configuration (sha256 %s): %w", cfg.SHA256, err)
		}
		log.Info("provenza proxy: configuration reported to the egress sensor", "config_sha256", cfg.SHA256)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := egress.New(cfg, key, log)
	if err := p.Start(ctx); err != nil { // no route table, nothing to forward
		return err
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("provenza proxy listening", "addr", cfg.Listen, "server", cfg.ServerURL)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func runAgent(identity, listen, upstream string, log *slog.Logger) error {
	id, err := egress.LoadAgentIdentity(identity)
	if err != nil {
		return err
	}
	h, err := egress.NewAgentMode(id, listen, upstream, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if listen == "" {
		return errors.New("agent mode needs -listen (unix:<path>, or a loopback address)")
	}
	ln, err := egress.AgentListener(listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if !strings.HasPrefix(listen, "unix:") {
		log.Warn("provenza agent mode on TCP: any local process that reaches it acts as the agent; "+
			"a unix socket keeps it to its owner", "addr", listen)
	}
	log.Info("provenza agent mode listening", "addr", listen, "agent", id.AgentID, "proxy", upstream)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// runConnect: `provenza-proxy connect <client>` (internal/connect).
func runConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	home, _ := os.UserHomeDir()
	defIdentity := os.Getenv("PROVENZA_IDENTITY")
	if defIdentity == "" {
		defIdentity = filepath.Join(home, ".config", "provenza", "provenza-agent.json")
	}
	identity := fs.String("identity", defIdentity, "the agent's identity file (provenza-agent.json from enrollment, mode 600)")
	proxy := fs.String("proxy", "auto", "the egress proxy; auto: http://127.0.0.1:8443 when one listens there, "+
		"else Provenza's own gateways (the identity's server)")
	port := fs.Int("port", 8480, "agent mode's port on 127.0.0.1")
	remove := fs.Bool("remove", false, "take the client's entry and agent mode out again")
	noService := fs.Bool("no-service", false, "do not run agent mode as a systemd --user service")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: provenza-proxy connect <%s> [flags]\n", strings.Join(connect.Names(), "|"))
		fs.PrintDefaults()
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		return 2
	}
	client, ok := connect.Clients[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown client %q: one of %s\n", args[0], strings.Join(connect.Names(), ", "))
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *port < 1 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "--port: 1-65535")
		return 2
	}
	abs, err := filepath.Abs(*identity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	id, err := egress.LoadAgentIdentity(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "the agent's identity (%s): %v\n", abs, err)
		fmt.Fprintln(os.Stderr, "  Agents -> the agent -> enroll it, save provenza-agent.json here (chmod 600), or pass --identity")
		return 1
	}
	if *proxy == "auto" {
		*proxy = autoUpstream(id.Server)
		if *proxy == "" {
			fmt.Fprintln(os.Stderr, "no egress proxy on 127.0.0.1:8443 and no server in the identity: pass --proxy")
			return 2
		}
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := egress.NewAgentMode(id, "127.0.0.1:1", *proxy, nil); err != nil { // the proxy's address is sound
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	verb := "Connecting"
	if *remove {
		verb = "Disconnecting"
	}
	fmt.Printf("%s %s as agent #%d\n", verb, client.Title, id.AgentID)
	err = connect.Do(connect.Options{Client: client, Identity: abs, AgentID: id.AgentID, Proxy: *proxy, Port: *port,
		Binary: self, Home: home, Remove: *remove, Service: !*noService, Out: os.Stdout, Run: connect.RunCommand})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// autoUpstream: the egress proxy on this host, else Provenza's own gateways.
func autoUpstream(server string) string {
	if c, err := net.DialTimeout("tcp", "127.0.0.1:8443", time.Second); err == nil {
		c.Close()
		return "http://127.0.0.1:8443"
	}
	if server == "" {
		return ""
	}
	return strings.TrimRight(server, "/") + "/api/v1"
}

// runEnroll: `provenza-proxy enroll` (internal/connect/enroll.go).
func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	home, _ := os.UserHomeDir()
	host, _ := os.Hostname()
	server := fs.String("server", "", "Provenza's address (https://...)")
	token := fs.String("token", os.Getenv("PROVENZA_ENROLL_TOKEN"), "the one-time enrollment token (pvz_enr_...); "+
		"$PROVENZA_ENROLL_TOKEN keeps it out of the process list")
	name := fs.String("name", "agent@"+host, "the agent's name, when the token names none")
	hybrid := fs.Bool("hybrid", false, "an Ed25519 + ML-DSA-65 key even when not required")
	identity := fs.String("identity", filepath.Join(home, ".config", "provenza", "provenza-agent.json"),
		"where the identity file goes (mode 600; one already there is kept as .old)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "usage: provenza-proxy enroll --server https://<provenza> --token pvz_enr_... [--name NAME]")
		return 2
	}
	id, purpose, err := connect.Enroll(connect.EnrollOptions{Server: *server, Token: *token, Name: *name,
		Hybrid: *hybrid, Path: *identity})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	what := "enrolled"
	if purpose == "rekey" {
		what = "has a new key"
	}
	scheme := "Ed25519"
	if id.PQPublicKey != "" {
		scheme = "Ed25519 + ML-DSA-65"
	}
	fmt.Printf("  ✓ agent #%d %s (%s, %s); its keys stay on this machine: %s\n", id.AgentID, what, scheme,
		id.KeyFingerprint, *identity)
	return 0
}
