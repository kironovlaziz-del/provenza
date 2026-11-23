// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"net/netip"
	"testing"
	"time"
)

func TestNameCache(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newNameCache()
	a, b := netip.MustParseAddr("104.18.7.192"), netip.MustParseAddr("2606:4700::6812:7c0")
	c.put(3, "api.openai.com", []netip.Addr{a, b}, now)

	if n, ok := c.get(3, a, now.Add(time.Minute)); !ok || n != "api.openai.com" {
		t.Fatal(n, ok)
	}
	// an IPv4 address the kernel reports mapped into IPv6 is the same address
	if n, ok := c.get(3, netip.AddrFrom16(a.As16()), now); !ok || n != "api.openai.com" {
		t.Fatal("mapped address", n, ok)
	}
	if n, ok := c.get(3, b, now); !ok || n != "api.openai.com" {
		t.Fatal("v6", n, ok)
	}
	// per workload: another one resolved nothing
	if _, ok := c.get(4, a, now); ok {
		t.Fatal("another workload's name")
	}
	// the latest answer wins, and it expires
	c.put(3, "chatgpt.com", []netip.Addr{a}, now.Add(time.Minute))
	if n, _ := c.get(3, a, now.Add(2*time.Minute)); n != "chatgpt.com" {
		t.Fatal(n)
	}
	if _, ok := c.get(3, a, now.Add(time.Minute+nameKeep+time.Second)); ok {
		t.Fatal("kept past its time")
	}
	// a workload gone from the policy is forgotten
	c.forget(func(wid uint32) bool { return wid != 3 })
	if _, ok := c.get(3, b, now); ok {
		t.Fatal("not forgotten")
	}
	// nil-safe: a daemon built without it (tests) notes nothing
	var none *nameCache
	none.put(1, "x", []netip.Addr{a}, now)
	if _, ok := none.get(1, a, now); ok {
		t.Fatal("nil cache answered")
	}
}

func TestNameCacheIsBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newNameCache()
	for i := 0; i < nameCacheMax+100; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		c.put(1, "host.example", []netip.Addr{ip}, now)
	}
	if n := len(c.byWid[1]); n > nameCacheMax {
		t.Fatalf("%d names kept", n)
	}
	// the newest is there
	last := nameCacheMax + 99
	if _, ok := c.get(1, netip.AddrFrom4([4]byte{10, byte(last >> 16), byte(last >> 8), byte(last)}), now); !ok {
		t.Fatal("the newest name was dropped")
	}
}
