// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Command provenza-proxy: the Provenza egress proxy (see internal/egress).
//
//	provenza-proxy -config /etc/provenza/proxy.json
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/egress"
)

func main() {
	path := flag.String("config", "/etc/provenza/proxy.json", "configuration file (JSON)")
	flag.Parse()
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
