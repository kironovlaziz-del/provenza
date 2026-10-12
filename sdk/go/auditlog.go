// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

// The local, signed, hash-chained audit log (JSON Lines) - standalone mode, and
// gaps (an action that ran but the server did not record). The format of the
// Python and JS SDKs: any of them verifies the others' logs. Only hashes of
// inputs and outputs are written, never content. Appends are serialized within
// the process; several processes should each use their own file.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

var signatureFields = map[string]bool{"signature": true, "pq_signature": true, "hash": true}

// AuditLog is the agent's local log.
type AuditLog struct {
	Path  string
	keys  Keys
	agent string
	mu    sync.Mutex
}

func without(e map[string]any, drop func(string) bool) map[string]any {
	out := make(map[string]any, len(e))
	for k, v := range e {
		if !drop(k) {
			out[k] = v
		}
	}
	return out
}

func entryHash(e map[string]any) (string, error) {
	return ContentHash(without(e, func(k string) bool { return k == "hash" }))
}

func lastEntry(f *os.File) (seq int64, hash string, err error) {
	st, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	var buf []byte
	for pos := st.Size(); pos > 0; {
		step := int64(4096)
		if pos < step {
			step = pos
		}
		pos -= step
		chunk := make([]byte, step)
		if _, err := f.ReadAt(chunk, pos); err != nil && err != io.EOF {
			return 0, "", err
		}
		buf = append(chunk, buf...)
		var lines [][]byte
		for _, l := range bytes.Split(buf, []byte("\n")) {
			if len(bytes.TrimSpace(l)) > 0 {
				lines = append(lines, l)
			}
		}
		if len(lines) > 1 || (len(lines) == 1 && pos == 0) {
			var e struct {
				Seq  int64  `json:"seq"`
				Hash string `json:"hash"`
			}
			if err := json.Unmarshal(lines[len(lines)-1], &e); err != nil {
				return 0, "", fmt.Errorf("provenza: last audit log entry: %w", err)
			}
			return e.Seq, e.Hash, nil
		}
	}
	return 0, genesisHash, nil
}

// Append writes one signed entry.
func (l *AuditLog) Append(fields map[string]any) (map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(l.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seq, prev, err := lastEntry(f)
	if err != nil {
		return nil, err
	}
	entry := map[string]any{"v": 1, "seq": seq + 1, "prev_hash": prev, "ts": time.Now().Unix(), "agent": l.agent}
	for k, v := range fields {
		entry[k] = v
	}
	sig, pq, err := l.keys.Sign(without(entry, func(k string) bool { return signatureFields[k] }))
	if err != nil {
		return nil, err
	}
	entry["signature"] = sig
	if pq != "" {
		entry["pq_signature"] = pq
	}
	if entry["hash"], err = entryHash(entry); err != nil {
		return nil, err
	}
	line, err := Canonical(entry)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		return nil, err
	}
	return entry, f.Sync()
}

// Entries reads the log.
func (l *AuditLog) Entries() ([]map[string]any, error) {
	return readEntries(l.Path)
}

func readEntries(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(sc.Text()))
		dec.UseNumber()
		var e map[string]any
		if err := dec.Decode(&e); err != nil {
			out = append(out, nil) // reported by VerifyAuditLog
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// VerifyAuditLog lists the problems in a log, by line; empty when every entry is
// signed by this key and the chain is unbroken.
func VerifyAuditLog(path, publicKey, pqPublicKey string) ([]string, error) {
	entries, err := readEntries(path)
	if err != nil {
		return nil, err
	}
	var problems []string
	prevHash, prevSeq := genesisHash, int64(0)
	for i, e := range entries {
		n := i + 1
		if e == nil {
			problems = append(problems, fmt.Sprintf("line %d: not JSON", n))
			continue
		}
		sn, _ := e["seq"].(json.Number) // a damaged entry is reported, never a panic
		seq, _ := sn.Int64()
		if seq != prevSeq+1 || e["prev_hash"] != prevHash {
			problems = append(problems, fmt.Sprintf("line %d: chain broken (an entry was removed, inserted or reordered)", n))
		}
		if h, err := entryHash(e); err != nil || e["hash"] != h {
			problems = append(problems, fmt.Sprintf("line %d: hash does not match the entry (altered)", n))
		}
		sig, _ := e["signature"].(string)
		pqSig, _ := e["pq_signature"].(string)
		if !verifySignatures(without(e, func(k string) bool { return signatureFields[k] }), sig, pqSig, publicKey, pqPublicKey) {
			problems = append(problems, fmt.Sprintf("line %d: signature does not verify", n))
		}
		prevHash, _ = e["hash"].(string)
		prevSeq = seq
	}
	return problems, nil
}
