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
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/egress"
)

func main() {
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
