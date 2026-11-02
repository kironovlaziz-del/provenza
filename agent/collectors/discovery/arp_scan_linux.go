package discovery

import (
	"encoding/binary"
	"log"
	"net"
	"syscall"
	"time"
)

// discoverViaARPScan finds live hosts on the local subnet by sending
// standard ARP REQUESTS ("who has 10.0.0.5? tell me") and listening for
// replies. Requires CAP_NET_RAW (checked by the caller).
//
// IMPORTANT - this is ARP *discovery*, not ARP *spoofing*. The two are
// completely different:
//   - We send ARP REQUESTs (opcode 1), the exact frame every operating
//     system emits whenever it needs to reach a neighbor. Asking "who
//     has this IP?" is how normal networking works.
//   - We NEVER send ARP REPLIES (opcode 2) claiming to own an IP we
//     don't. That - poisoning other hosts' ARP caches to intercept their
//     traffic - is spoofing/MITM, and this code does not and will not do
//     it. There is no path here that forges a reply or answers on behalf
//     of another address.
//
// The result is simply a list of which IPs are alive and their MACs -
// the same thing `arp -a` or `ip neigh` shows after normal use.
func discoverViaARPScan(rep *Reporter) {
	info, err := primaryInterface()
	if err != nil {
		log.Printf("[Discovery/ARP] no usable interface: %v", err)
		return
	}
	hosts := enumerateHosts(info)
	if len(hosts) == 0 {
		log.Printf("[Discovery/ARP] subnet too large or empty; skipping ARP scan")
		return
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		log.Printf("[Discovery/ARP] cannot open raw socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	ll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ARP),
		Ifindex:  info.iface.Index,
	}

	// Receiver goroutine: read ARP replies until the deadline.
	replies := make(map[string]net.HardwareAddr)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
			&syscall.Timeval{Sec: 1, Usec: 0})
		buf := make([]byte, 1500)
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				continue // timeout tick - re-check deadline
			}
			ip, mac, ok := parseARPReply(buf[:n], info.mac)
			if ok {
				replies[ip] = mac
			}
		}
	}()

	// Send an ARP request for every candidate host.
	for _, target := range hosts {
		frame := buildARPRequest(info.mac, info.ip, target)
		if err := syscall.Sendto(fd, frame, 0, ll); err != nil {
			// A single send failure (e.g. ENOBUFS under load) shouldn't
			// abort the whole scan.
			continue
		}
		time.Sleep(2 * time.Millisecond) // gentle pacing, avoid flooding
	}

	<-done

	for ipStr, mac := range replies {
		log.Printf("[Discovery/ARP] Live host: %s (%s)", ipStr, mac)
		rep.Add(DiscoveredService{
			ServiceType:   "host",
			Host:          ipStr,
			DiscoveredVia: "arp_scan",
			Details:       map[string]interface{}{"mac": mac.String()},
		})
	}
	log.Printf("[Discovery/ARP] scan complete: %d live hosts", len(replies))
}

// buildARPRequest constructs a broadcast Ethernet frame containing an
// ARP request asking who owns targetIP. Opcode is always 1 (request).
func buildARPRequest(srcMAC net.HardwareAddr, srcIP, targetIP net.IP) []byte {
	frame := make([]byte, 42) // 14 Ethernet + 28 ARP

	// Ethernet header
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst: broadcast
	copy(frame[6:12], srcMAC)                                    // src: us
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)             // EtherType ARP

	// ARP payload
	binary.BigEndian.PutUint16(frame[14:16], 1)      // HTYPE: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // PTYPE: IPv4
	frame[18] = 6                                    // HLEN
	frame[19] = 4                                    // PLEN
	binary.BigEndian.PutUint16(frame[20:22], 1)      // OPER: 1 = REQUEST (never 2)
	copy(frame[22:28], srcMAC)                       // sender MAC
	copy(frame[28:32], srcIP.To4())                  // sender IP
	// target MAC left zero (unknown - that's what we're asking)
	copy(frame[38:42], targetIP.To4()) // target IP
	return frame
}

// parseARPReply extracts (ip, mac) from an ARP reply frame, ignoring our
// own frames and non-replies. Returns ok=false for anything else.
func parseARPReply(frame []byte, ourMAC net.HardwareAddr) (string, net.HardwareAddr, bool) {
	if len(frame) < 42 {
		return "", nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0806 {
		return "", nil, false // not ARP
	}
	if binary.BigEndian.Uint16(frame[20:22]) != 2 {
		return "", nil, false // not a reply
	}
	senderMAC := net.HardwareAddr(append([]byte(nil), frame[22:28]...))
	senderIP := net.IP(append([]byte(nil), frame[28:32]...))
	if senderMAC.String() == ourMAC.String() {
		return "", nil, false // our own frame echoed back
	}
	return senderIP.String(), senderMAC, true
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
