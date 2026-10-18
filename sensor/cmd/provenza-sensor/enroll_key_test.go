// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package main

import (
	"io"
	"os"
	"testing"
)

func pipeWith(t *testing.T, s string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.WriteString(w, s); _ = w.Close() }()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestResolveKey(t *testing.T) {
	t.Setenv(keyEnv, "")

	if k, err := resolveKey("pvz_sensor_flag", pipeWith(t, ""), io.Discard); err != nil || k != "pvz_sensor_flag" {
		t.Fatalf("flag: %q %v", k, err)
	}
	if k, err := resolveKey("-", pipeWith(t, "pvz_sensor_stdin\n"), io.Discard); err != nil || k != "pvz_sensor_stdin" {
		t.Fatalf("stdin: %q %v", k, err)
	}
	t.Setenv(keyEnv, "pvz_sensor_env")
	if k, err := resolveKey("", pipeWith(t, ""), io.Discard); err != nil || k != "pvz_sensor_env" {
		t.Fatalf("env: %q %v", k, err)
	}
	t.Setenv(keyEnv, "")
	// no key and no terminal to ask on: an error, not a hang
	if _, err := resolveKey("", pipeWith(t, ""), io.Discard); err == nil {
		t.Fatal("want an error without a key or a terminal")
	}
}
