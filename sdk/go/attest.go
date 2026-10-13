// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Attest proves where this agent runs. evidence is the workload's token: a
// Kubernetes projected ServiceAccount token, or an OIDC token from GitHub
// Actions, Google Cloud, Azure, ... The agent signs the token's hash with its
// own key over a server challenge, so a copied token is useless without the
// key. The result is the server's record (ok, reason, identity, valid_until).
func (a *Agent) Attest(ctx context.Context, evidence string) (map[string]any, error) {
	c, err := a.connected()
	if err != nil {
		return nil, err
	}
	id := a.AgentID()
	if id == nil {
		return nil, fmt.Errorf("provenza: the agent has no id")
	}
	ch, err := c.post(ctx, fmt.Sprintf("/agents/%d/attestation/challenge", *id), map[string]any{}, true)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(evidence)
	sum := sha256.Sum256([]byte(token))
	challenge, kind := str(ch, "challenge"), str(ch, "kind")
	sig, pq, err := a.identity.Keys.Sign(map[string]any{"type": "provenza.agent.attestation", "v": 1,
		"challenge": challenge, "agent_id": *id, "kind": kind, "evidence_sha256": hex.EncodeToString(sum[:])})
	if err != nil {
		return nil, err
	}
	body := map[string]any{"challenge": challenge, "kind": kind, "evidence": token, "signature": sig}
	if pq != "" {
		body["pq_signature"] = pq
	}
	return c.post(ctx, fmt.Sprintf("/agents/%d/attestation", *id), body, true)
}
