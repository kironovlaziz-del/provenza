// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/kern"
)

// Uninstall detaches the kernel programs and removes the sensor's state.
// It does not remove the binary or the systemd unit: those belong to the
// package manager.
func Uninstall(ctx context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if err := kern.Detach(cfg.PinDir); err != nil {
		slog.Warn("detach", "err", err)
	}
	if err := os.RemoveAll(cfg.StateDir); err != nil {
		slog.Warn("remove state", "err", err)
	}
	if cfg.RunSocket != "" {
		_ = os.Remove(cfg.RunSocket)
	}
	slog.Info("uninstalled", "pin_dir", cfg.PinDir)
	_ = ctx
	return nil
}
