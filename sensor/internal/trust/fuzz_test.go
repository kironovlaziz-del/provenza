// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

import (
	"encoding/base64"
	"testing"
)

// The X-Provenza-Request header comes from the agent: whatever it holds is
// refused with an error or read into a request with its payload, signature
// and key - never a panic.
func FuzzParseSignedRequest(f *testing.F) {
	enc := base64.RawURLEncoding.EncodeToString
	for _, s := range []string{"", "!!!", enc([]byte(`{}`)), enc([]byte(`[]`)), enc([]byte(`null`)),
		enc([]byte(`{"payload":{"a":1},"signature":"s","public_key":"k"}`)),
		enc([]byte(`{"payload":[],"signature":1,"public_key":null}`)),
		enc([]byte(`{"payload":{},"signature":"s","public_key":"k","pq_signature":"p","pq_public_key":"q"}`))} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		r, err := ParseSignedRequest(header)
		if err != nil {
			if r != nil {
				t.Fatal("a request alongside an error")
			}
			return
		}
		if r.Payload == nil || r.Signature == "" || r.PublicKey == "" {
			t.Fatalf("accepted without payload, signature or key: %+v", r)
		}
	})
}

// A release or policy document fetched from the server: parsed or refused.
func FuzzParseDocument(f *testing.F) {
	for _, s := range []string{`{}`, `[]`, `{"a":1}`, `{"a":1}{}`, `{"a":1e999}`, ``} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		doc, err := ParseDocument(raw)
		if err == nil && doc == nil {
			t.Fatal("no document and no error")
		}
	})
}
