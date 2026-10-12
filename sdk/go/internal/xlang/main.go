// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Command xlang is the Go side of the cross-language tests
// (backend/tests/test_sdk_go.py), not part of the SDK's API.
//
//	xlang record '{"server":..,"identity":..,"check":{..},"tool":..,"input":{..},"output":{..}}'
//	    load the identity, govern one call under the given (real) check, print the
//	    record body the SDK built and signed - the test sends it to the real server
//	xlang standalone IDENTITY_PATH
//	    write a standalone audit log, print its path and the public key
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	provenza "github.com/kironovlaziz-del/provenza/sdk/go"
)

type capture struct {
	check    []byte
	recorded []byte
}

func (c *capture) RoundTrip(r *http.Request) (*http.Response, error) {
	resp := func(body []byte) *http.Response {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(bytes.NewReader(body)), Request: r}
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/agents/actions/check"):
		return resp(c.check), nil
	case strings.HasSuffix(r.URL.Path, "/agents/actions/record"):
		c.recorded, _ = io.ReadAll(r.Body)
		return resp([]byte(`{"id":1}`)), nil
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	switch os.Args[1] {
	case "record":
		var cfg struct {
			Server, Identity, Tool string
			Check                  json.RawMessage
			Input, Output          map[string]any
		}
		if err := json.Unmarshal([]byte(os.Args[2]), &cfg); err != nil {
			return err
		}
		c := &capture{check: cfg.Check}
		agent, err := provenza.New(ctx, provenza.Config{ServerURL: cfg.Server, IdentityPath: cfg.Identity,
			HTTPClient: &http.Client{Transport: c}})
		if err != nil {
			return err
		}
		if _, err := provenza.Call(ctx, agent, cfg.Tool, cfg.Input, func(context.Context) (map[string]any, error) {
			return cfg.Output, nil
		}); err != nil {
			return err
		}
		_, err = os.Stdout.Write(c.recorded)
		return err
	case "standalone":
		agent, err := provenza.New(ctx, provenza.Config{Name: "go-solo", IdentityPath: os.Args[2]})
		if err != nil {
			return err
		}
		for i := 0; i < 3; i++ {
			if _, err := provenza.Call(ctx, agent, "calc.add", map[string]any{"x": i, "y": 1e-7},
				func(context.Context) (float64, error) { return float64(i) + 1e-7, nil }); err != nil {
				return err
			}
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"log": agent.AuditLog().Path,
			"pub": agent.Identity().Keys.PublicKey})
	}
	return fmt.Errorf("unknown command %q", os.Args[1])
}
