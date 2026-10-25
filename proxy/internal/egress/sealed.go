// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// Credentials sealed to this proxy (backend/app/pvp/sealed.py; docs/pvp/edge.md,
// section 4). An administrator types a credential in the browser, which seals
// it to this proxy's X25519 key; the server stores the envelope and cannot
// open it. The proxy opens it here, keeps the credential in memory only, and
// uses it only for the object the envelope's context names:
//
//	shared = X25519(proxy private, ephemeral public)
//	key    = HKDF-SHA256(shared, salt = epk || proxy public,
//	                     info = "provenza sealed credential v1" || canonical(context))
//	plain  = AES-256-GCM-Open(key, nonce, ct, aad = canonical(context))
//
// The X25519 key is derived from the proxy's signing seed, so the one key
// file (state_dir, or signing_key_file) holds both; its public half is
// registered once, signed by the signing key.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

const (
	sealedAlg       = "X25519-HKDF-SHA256-A256GCM"
	sealedInfo      = "provenza sealed credential v1"
	encryptionInfo  = "provenza proxy encryption key v1"
	keyStatementTyp = "provenza.proxy.encryption_key"
	maxCredential   = 8000
)

// hkdfSHA256: RFC 5869 (crypto/hkdf is newer than the Go this module targets).
func hkdfSHA256(secret, salt, info []byte, n int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// opener holds the proxy's X25519 key.
type opener struct {
	priv *ecdh.PrivateKey
	pub  []byte
}

func newOpener(signing ed25519.PrivateKey) (*opener, error) {
	k := hkdfSHA256(signing.Seed(), nil, []byte(encryptionInfo), 32)
	priv, err := ecdh.X25519().NewPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return &opener{priv: priv, pub: priv.PublicKey().Bytes()}, nil
}

func (o *opener) publicKey() string { return base64.StdEncoding.EncodeToString(o.pub) }

// keyStatement: what the signing key signs about the encryption key.
func keyStatement(encryptionKey string) ([]byte, error) {
	v, err := canon.Of(map[string]any{"type": keyStatementTyp, "v": 1, "key": encryptionKey})
	if err != nil {
		return nil, err
	}
	return canon.Bytes(v)
}

func b64(m map[string]any, k string) ([]byte, error) {
	s, _ := m[k].(string)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || s == "" {
		return nil, fmt.Errorf("%s is not base64", k)
	}
	return raw, nil
}

// origin: scheme://host[:port] of a URL - lower case, the default port left
// out, an IPv6 host in brackets ("" when it has none). The same as
// backend/app/pvp/sealed.py origin().
func origin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	def := map[string]string{"http": "80", "https": "443"}[scheme]
	host := strings.ToLower(u.Hostname())
	if def == "" || host == "" {
		return ""
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 {
			return ""
		}
		port = strconv.Itoa(n)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" || port == def {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + port
}

// open: the credential in an envelope and the upstream origin it may go to,
// if it was sealed to this key for the context want ({org_id, object,
// object_id, proxy_id}) - the upstream is the envelope's own (authenticated).
func (o *opener) open(env map[string]any, want map[string]any) (string, string, error) {
	if v := fmt.Sprint(env["v"]); v != "1" || env["alg"] != sealedAlg {
		return "", "", errors.New("unknown version or algorithm")
	}
	ctx, _ := env["context"].(map[string]any)
	if ctx == nil {
		return "", "", errors.New("no context")
	}
	upstream, _ := ctx["upstream"].(string)
	if upstream == "" || origin(upstream) != upstream {
		return "", "", errors.New("no upstream origin")
	}
	got, err := canon.Bytes(ctx)
	if err != nil {
		return "", "", err
	}
	full := map[string]any{"upstream": upstream}
	for k, v := range want {
		full[k] = v
	}
	wv, err := canon.Of(full)
	if err != nil {
		return "", "", err
	}
	exp, err := canon.Bytes(wv)
	if err != nil {
		return "", "", err
	}
	if !hmac.Equal(got, exp) {
		return "", "", errors.New("sealed for another object or proxy")
	}
	epk, err := b64(env, "epk")
	if err != nil {
		return "", "", err
	}
	nonce, err := b64(env, "nonce")
	if err != nil {
		return "", "", err
	}
	ct, err := b64(env, "ct")
	if err != nil {
		return "", "", err
	}
	if len(epk) != 32 || len(nonce) != 12 || len(ct) <= 16 || len(ct) > maxCredential+16 {
		return "", "", errors.New("wrong sizes")
	}
	peer, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return "", "", err
	}
	shared, err := o.priv.ECDH(peer)
	if err != nil {
		return "", "", err
	}
	key := hkdfSHA256(shared, append(append([]byte{}, epk...), o.pub...), append([]byte(sealedInfo), got...), 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	plain, err := gcm.Open(nil, nonce, ct, got)
	if err != nil {
		return "", "", errors.New("does not open with this proxy's key")
	}
	return string(plain), upstream, nil
}

// credKey names an object a credential is for.
type credKey struct {
	Object string
	ID     string // as the server sends it (a JSON number's text)
}

// openedCredential: a credential and the only origin it may be sent to.
type openedCredential struct {
	Value    string
	Upstream string
}
