// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

import "fmt"

// ConfigError: the agent is not set up (no server, no identity, no token, ...).
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return "provenza: " + e.Msg }

// UnavailableError: the server could not be reached or failed (network, timeout,
// 5xx). In connected mode the function did NOT run (fail-closed).
type UnavailableError struct{ Msg string }

func (e *UnavailableError) Error() string { return "provenza: server unavailable: " + e.Msg }

// RequestError: the server refused the request itself (4xx).
type RequestError struct {
	Status int
	Detail any
	Path   string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("provenza: %s: HTTP %d: %v", e.Path, e.Status, e.Detail)
}

// DeniedError: Provenza's verdict refused the call; the function did not run.
// The attempt is recorded (ActionID). Decision "pending_approval" means a
// human must approve first - see ApprovalRequired.
type DeniedError struct {
	Tool         string
	Reason       string
	Decision     string
	IncidentType string
	CheckID      string
	ActionID     *int64
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("provenza: %s: %s: %s", e.Tool, e.Decision, e.Reason)
}

// ApprovalRequired tells a call waiting for a human from a plain denial.
func (e *DeniedError) ApprovalRequired() bool { return e.Decision == "pending_approval" }
