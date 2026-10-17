// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Package bpfobj holds the compiled kernel program (bpf/sensor.bpf.c, built
// by `make bpf`) and the Go mirrors of its map keys, values and events. The
// layouts here must match the C structs byte for byte; bpfobj_test.go checks
// the sizes against the object's BTF.
package bpfobj

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
)

//go:embed sensor.bpf.o
var object []byte

// Program names in the object, by what they need from the kernel.
var (
	// Required: without them there is no containment.
	CoreProgs = []string{
		"pvz_connect4", "pvz_connect6", "pvz_sendmsg4", "pvz_sendmsg6",
		"pvz_recvmsg4", "pvz_recvmsg6", "pvz_getpeername4", "pvz_getpeername6",
		"pvz_sock_create", "pvz_egress", "pvz_ingress",
	}
	// Optional: BPF LSM (socket families) and BTF (new cgroups governed at
	// creation). Their absence is reported, not fatal.
	LSMProgs   = []string{"pvz_socket_family"}
	MkdirProgs = []string{"pvz_cgroup_mkdir", "pvz_cgroup_rmdir"}
)

const (
	ModeObserve = 0
	ModeAlert   = 1
	ModeEnforce = 2

	DNSOff    = 0
	DNSListed = 1
	DNSAny    = 2

	CgGoverned = 1
	CgExempt   = 2
	CgPending  = 3

	ActObserved = 1
	ActAlerted  = 2
	ActBlocked  = 3
	ActAllowed  = 4

	KindConnect = 1
	KindSend    = 2
	KindSocket  = 3
	KindPacket  = 4
	KindIngress = 5
	KindDNS     = 6 // from the DNS proxy, not the kernel
	KindFamily  = 7

	EvViolation = 1
	EvMkdir     = 2
	EvRmdir     = 3
	EvAllowed   = 4

	DirEgress  = 0
	DirIngress = 1

	WlDNSv6 = 0x1

	StatEventsLost = 0
	StatMkdirLost  = 1
	StatAllowed    = 2
	StatDenied     = 3
	StatObserved   = 4

	PathLen = 512
)

type CgEntry struct {
	Wid   uint32
	Kind  uint32
	Since uint64
}

type WlKey struct {
	Gen uint32
	Wid uint32
}

type WlCfg struct {
	Mode     uint8
	Isolated uint8
	DNS      uint8
	Flags    uint8
	DNSPort  uint16
	Pad      uint16
}

type LPM4 struct {
	Prefixlen uint32
	Gen       uint32
	Wid       uint32
	Dir       uint8
	Proto     uint8
	Port      uint16
	Addr      [4]byte
}

type LPM6 struct {
	Prefixlen uint32
	Gen       uint32
	Wid       uint32
	Dir       uint8
	Proto     uint8
	Port      uint16
	Addr      [16]byte
}

// FixedBits is the exact-match part of an LPM key: gen, wid, dir, proto, port.
const FixedBits = 96

type Globals struct {
	Gen   uint32
	Epoch uint32
}

type Event struct {
	Type     uint8
	Action   uint8
	Kind     uint8
	Proto    uint8
	Family   uint8
	Isolated uint8
	Port     uint16
	Wid      uint32
	Pid      uint32
	UID      uint32
	Count    uint32
	Cgid     uint64
	Addr     [16]byte
	Comm     [16]byte
	TsNs     uint64
}

type MkdirEvent struct {
	Type uint8
	Pad  [7]uint8
	Cgid uint64
	Path [PathLen]byte
}

// Spec parses the embedded object.
func Spec() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("the embedded eBPF object: %w", err)
	}
	return spec, nil
}
