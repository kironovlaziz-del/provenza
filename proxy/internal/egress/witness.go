// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// The proxy's own key and receipts (docs/pvp/edge.md, section 4;
// backend/app/pvp/witness.py). The key is generated here, on this host, and
// never leaves it; its public half is registered with Provenza once. For
// every request it forwarded - or refused under the signed policy - the
// proxy signs a receipt naming the action exactly, and appends it to its own
// hash-chained log (receipts.jsonl): each line carries the SHA-256 of the
// line before, so the log cannot be edited without breaking the chain.

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

const (
	keyFile     = "proxy-ed25519.key"
	logFile     = "receipts.jsonl"
	receiptType = "provenza.proxy.receipt"
)

type witness struct {
	key  ed25519.PrivateKey
	path string

	mu   sync.Mutex
	seq  int64
	prev string // SHA-256 (hex) of the last line, "" before the first
}

// NewSigningKey: a fresh key as a file holds it (base64 of the Ed25519 seed),
// and the fingerprint Provenza will show for it.
func NewSigningKey() (string, string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", "", err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return base64.StdEncoding.EncodeToString(seed), "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not an Ed25519 seed (make one with provenza-proxy -genkey)", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// loadKey reads the proxy's key (keyPath, else state_dir), or makes one in
// state_dir (0600, in a 0700 directory).
func loadKey(dir, keyPath string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if keyPath != "" {
		return readKey(keyPath)
	}
	path := filepath.Join(dir, keyFile)
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		enc, _, err := NewSigningKey()
		if err != nil {
			return nil, err
		}
		enc += "\n"
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.WriteString(enc); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return readKey(path)
}

func newWitness(dir, keyPath string) (*witness, error) {
	key, err := loadKey(dir, keyPath)
	if err != nil {
		return nil, err
	}
	w := &witness{key: key, path: filepath.Join(dir, logFile)}
	// continue the chain where the log ends
	f, err := os.Open(w.path)
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			sum := sha256.Sum256(line)
			w.prev = hex.EncodeToString(sum[:])
			w.seq++
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", w.path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return w, nil
}

func (w *witness) publicKey() string {
	return base64.StdEncoding.EncodeToString(w.key.Public().(ed25519.PublicKey))
}

// sign makes the receipt for an action, logs it and returns {statement, signature}.
// fields: check_id, agent_id, chain_id, action_type, tool_name, input_sha256,
// output_sha256, decision, agent_signature, policy.
func (w *witness) sign(fields map[string]any) (map[string]any, error) {
	return w.signAs(receiptType, fields)
}

// signAs signs and logs a statement of another type in the same chain (a
// reconciliation report, a lift: killswitch.go).
func (w *witness) signAs(typ string, fields map[string]any) (map[string]any, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := map[string]any{"type": typ, "v": 1, "issued_at": time.Now().Unix(),
		"log": map[string]any{"seq": w.seq + 1, "prev": w.prev}}
	for k, v := range fields {
		st[k] = v
	}
	parsed, err := canon.Of(st)
	if err != nil {
		return nil, err
	}
	text, err := canon.Text(parsed)
	if err != nil {
		return nil, err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(w.key, []byte(text)))
	line, err := canon.Bytes(map[string]any{"statement": parsed, "signature": sig})
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(line)
	w.prev, w.seq = hex.EncodeToString(sum[:]), w.seq+1
	return map[string]any{"statement": parsed, "signature": sig}, nil
}
