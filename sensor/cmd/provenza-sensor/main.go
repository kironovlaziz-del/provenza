// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Command provenza-sensor is the egress sensor daemon. It enforces the
// Provenza policy via cgroup BPF programs, resolves DNS through a local
// proxy, reports violations, and exposes `run` for one-off agent commands.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kironovlaziz-del/provenza/sensor/internal/daemon"
)

// version is set with -ldflags at build time.
var version = "dev"

func main() {
	var (
		cfgPath   = flag.String("config", "/etc/provenza-sensor/sensor.json", "path to sensor.json")
		agentID   = flag.Int64("agent", 0, "agent id (run subcommand)")
		showVer   = flag.Bool("version", false, "print version and exit")
		uninstall = flag.Bool("uninstall", false, "detach the sensor and remove its state")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("provenza-sensor", version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	switch {
	case *uninstall:
		if err := daemon.Uninstall(ctx, *cfgPath); err != nil {
			slog.Error("uninstall", "err", err)
			os.Exit(1)
		}
		return

	case flag.Arg(0) == "enroll":
		enrollCmd(ctx, flag.Args()[1:])
		return

	case flag.Arg(0) == "run":
		// flag.Parse stops at the first non-flag ("run"), so "--agent N"
		// must come before it. The "--" separator is a convention, not
		// parsed by flag: strip it here.
		cmd := flag.Args()[1:]
		if len(cmd) > 0 && cmd[0] == "--" {
			cmd = cmd[1:]
		}
		if len(cmd) == 0 {
			slog.Error("run: no command")
			os.Exit(2)
		}
		if *agentID == 0 {
			slog.Error("run: --agent N is required")
			os.Exit(2)
		}
		if err := daemon.RunCommand(ctx, *cfgPath, *agentID, cmd); err != nil {
			slog.Error("run", "err", err)
			os.Exit(1)
		}
		return
	}

	d, err := daemon.New(*cfgPath, version)
	if err != nil {
		slog.Error("init", "err", err)
		os.Exit(1)
	}
	if err := d.Run(ctx); err != nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
