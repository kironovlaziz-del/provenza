// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/kern"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsServers runs one UDP DNS listener per governed workload, on
// 127.0.0.1:<dnsBasePort+index>. The BPF program redirects a workload's DNS
// queries to that port.
type dnsServers struct {
	d        *Daemon
	upstream []string

	mu  sync.Mutex
	svc map[uint32]*dnsServer // workload id -> running server
}

type dnsServer struct {
	d       *Daemon
	wid     uint32
	port    uint16
	conn    *net.UDPConn
	names   map[string]bool
	suffix  []string
	allow   []config.Allow
	mode    string
	work    chan dnsWork
	stop    chan struct{}
	stopped chan struct{}

	// Counters for `status`. Only atomic operations; never under any lock.
	totalQueries   atomic.Uint64
	allowedQueries atomic.Uint64
	deniedQueries  atomic.Uint64
	lastQueryAt    atomic.Int64 // unix nanoseconds
}

type dnsWork struct {
	addr  *net.UDPAddr
	query []byte
}

func newDNSServers(d *Daemon) *dnsServers {
	return &dnsServers{
		d:        d,
		upstream: upstreams(),
		svc:      map[uint32]*dnsServer{},
	}
}

// upstreams reads /etc/resolv.conf; falls back to a public resolver.
func upstreams() []string {
	u := upstreamFromResolvConf()
	if len(u) == 0 {
		return []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return u
}

func (s *dnsServers) start(ctx context.Context, wg *sync.WaitGroup) {
	s.mu.Lock()
	all := make([]*dnsServer, 0, len(s.svc))
	for _, srv := range s.svc {
		all = append(all, srv)
	}
	s.mu.Unlock()
	for _, srv := range all {
		wg.Add(1)
		go func(sv *dnsServer) {
			defer wg.Done()
			sv.run(ctx, s.upstream)
		}(srv)
	}
}

// reload applies the current workload map: starts servers for new
// workloads, stops servers for removed ones, and updates names/allow lists
// for existing ones.
func (s *dnsServers) reload(ctx context.Context, wls map[uint32]*wlState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for wid, srv := range s.svc {
		ws, ok := wls[wid]
		if !ok || ws.dnsPort == 0 {
			srv.close()
			delete(s.svc, wid)
			continue
		}
		srv.names = ws.dnsNames
		srv.suffix = ws.dnsSfx
		srv.allow = ws.cfg.EgressAllow
		srv.mode = ws.cfg.DNS
	}

	for wid, ws := range wls {
		if ws.dnsPort == 0 {
			continue
		}
		if _, ok := s.svc[wid]; ok {
			continue
		}
		srv, err := newDNSServer(s.d, wid, ws)
		if err != nil {
			slog.Warn("dns: listen", "wid", wid, "port", ws.dnsPort, "err", err)
			continue
		}
		s.svc[wid] = srv
		go srv.run(ctx, s.upstream)
	}
}

func (s *dnsServers) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for wid, srv := range s.svc {
		srv.close()
		delete(s.svc, wid)
	}
}

func newDNSServer(d *Daemon, wid uint32, ws *wlState) (*dnsServer, error) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(ws.dnsPort)}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &dnsServer{
		d:       d,
		wid:     wid,
		port:    ws.dnsPort,
		conn:    conn,
		names:   ws.dnsNames,
		suffix:  ws.dnsSfx,
		allow:   ws.cfg.EgressAllow,
		mode:    ws.cfg.DNS,
		work:    make(chan dnsWork, 64),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}, nil
}

func (s *dnsServer) close() {
	select {
	case <-s.stop:
		return
	default:
	}
	close(s.stop)
	_ = s.conn.Close()
	<-s.stopped
}

func (s *dnsServer) run(ctx context.Context, upstream []string) {
	defer close(s.stopped)

	// Reader loop.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := make([]byte, n)
			copy(q, buf[:n])
			select {
			case s.work <- dnsWork{addr: addr, query: q}:
			default: // drop when overloaded
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case w := <-s.work:
			s.handle(w, upstream)
		}
	}
}

func (s *dnsServer) handle(w dnsWork, upstream []string) {
	var p dnsmessage.Parser
	hdr, err := p.Start(w.query)
	if err != nil || hdr.RCode != dnsmessage.RCodeSuccess {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")

	s.totalQueries.Add(1)
	s.lastQueryAt.Store(time.Now().UnixNano())

	if s.mode == "listed" && !s.nameAllowed(name) {
		s.deniedQueries.Add(1)
		resp := refuse(w.query, hdr.ID)
		_, _ = s.conn.WriteToUDP(resp, w.addr)
		return
	}
	s.allowedQueries.Add(1)

	resp, err := forward(w.query, upstream)
	if err != nil {
		slog.Debug("dns forward", "name", name, "err", err)
		return
	}
	_, _ = s.conn.WriteToUDP(resp, w.addr)

	// Feed resolved addresses back into the kernel allow map.
	ports, protos := s.portsFor(name)
	if len(ports) == 0 {
		return
	}
	for _, ip := range extractIPs(resp) {
		prefix := netip.PrefixFrom(ip, ip.BitLen())
		var rules []kern.Rule
		for _, port := range ports {
			for _, proto := range protos {
				rules = append(rules, kern.Rule{
					Dir:   bpfobj.DirEgress,
					Proto: proto,
					Port:  uint16(port),
					Net:   prefix,
				})
			}
		}
		if len(rules) > 0 {
			if err := s.d.kernel.AddLive(s.wid, rules); err != nil {
				slog.Warn("add live rule", "wid", s.wid, "err", err)
			}
		}
	}
}

// nameAllowed reports whether the workload's listed mode allows name.
func (s *dnsServer) nameAllowed(name string) bool {
	if s.names[name] {
		return true
	}
	for _, sfx := range s.suffix {
		if strings.HasSuffix(name, sfx) && len(name) > len(sfx) {
			return true
		}
	}
	return false
}

// portsFor returns the ports and protocols that apply to a name when it is
// resolved. Any EgressAllow entry whose Dest matches the name contributes.
func (s *dnsServer) portsFor(name string) ([]int, []uint8) {
	seenPort := map[int]bool{}
	seenProto := map[uint8]bool{}
	var ports []int
	var protos []uint8
	for _, a := range s.allow {
		d := strings.TrimSuffix(strings.ToLower(a.Dest), ".")
		if d == "" {
			continue
		}
		if d != name && !(strings.HasPrefix(d, "*.") && strings.HasSuffix(name, d[1:]) && len(name) > len(d)-1) {
			continue
		}
		for _, p := range a.Ports {
			if !seenPort[p] {
				seenPort[p] = true
				ports = append(ports, p)
			}
		}
		for _, pr := range a.Protocols {
			n := protoNum(pr)
			if !seenProto[n] {
				seenProto[n] = true
				protos = append(protos, n)
			}
		}
	}
	return ports, protos
}

// forward sends the raw query to the first reachable upstream and returns
// the raw response.
func forward(query []byte, upstream []string) ([]byte, error) {
	var last error
	for _, up := range upstream {
		c, err := net.DialTimeout("udp", up, 2*time.Second)
		if err != nil {
			last = err
			continue
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(query); err != nil {
			_ = c.Close()
			last = err
			continue
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		_ = c.Close()
		if err != nil {
			last = err
			continue
		}
		return buf[:n], nil
	}
	if last == nil {
		last = errors.New("no upstream")
	}
	return nil, last
}

// refuse builds a REFUSED response for the same ID.
func refuse(query []byte, id uint16) []byte {
	out := make([]byte, len(query))
	copy(out, query)
	if len(out) < 12 {
		return out
	}
	// QR=1, RCODE=5 (REFUSED)
	out[2] = 0x81
	out[3] = 0x85
	// Clear ANCOUNT and NSCOUNT.
	out[6], out[7] = 0, 0
	out[8], out[9] = 0, 0
	return out
}

// extractIPs returns all A and AAAA addresses in the answer section.
// dnsmessage does not expose section counts, so we read answers until
// ErrSectionDone.
func extractIPs(msg []byte) []netip.Addr {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	var out []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return out
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out
			}
			out = append(out, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return out
			}
		}
	}
	return out
}

// stats returns the DNS counters of every running per-workload server.
// cgByWid is only used to filter out workloads no longer in the policy,
// so the output stays in step with what `status` shows for workloads.
func (s *dnsServers) stats(cgByWid map[uint32]int) []DNSSection {
	s.mu.Lock()
	servers := make([]*dnsServer, 0, len(s.svc))
	for _, srv := range s.svc {
		servers = append(servers, srv)
	}
	s.mu.Unlock()

	out := make([]DNSSection, 0, len(servers))
	for _, srv := range servers {
		sec := DNSSection{
			WorkloadID: srv.wid,
			Port:       srv.port,
			Total:      srv.totalQueries.Load(),
			Allowed:    srv.allowedQueries.Load(),
			Denied:     srv.deniedQueries.Load(),
		}
		if ns := srv.lastQueryAt.Load(); ns > 0 {
			t := time.Unix(0, ns).UTC()
			sec.LastQueryAt = &t
		}
		out = append(out, sec)
	}
	// Stable order by workload id, so output is diffable.
	sort.Slice(out, func(i, j int) bool { return out[i].WorkloadID < out[j].WorkloadID })
	return out
}
