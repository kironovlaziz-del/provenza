package discovery

import (
	"encoding/binary"
	"log"
	"net"
	"syscall"
	"time"
)

// discoverViaPassiveDHCP listens for DHCP traffic and reports the DHCP
// servers it observes. Requires CAP_NET_RAW (checked by the caller).
//
// Strictly PASSIVE: it opens a raw socket in listen-only mode and never
// transmits anything - no DHCPDISCOVER, no requests, nothing. It simply
// watches the DHCP OFFER/ACK messages that servers broadcast in the
// normal course of the network handing out leases, and notes the server
// identity from them. Because it never injects traffic, it can't
// interfere with real DHCP on the segment.
//
// It listens for a bounded window per sweep. DHCP is bursty and
// infrequent (leases renew on the order of hours), so a short listen may
// catch nothing - that's expected, not a failure. Over repeated sweeps
// it builds up the picture as leases happen.
func discoverViaPassiveDHCP(rep *Reporter) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		log.Printf("[Discovery/DHCP] cannot open raw socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 1, Usec: 0})

	seen := map[string]bool{}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue // recv timeout - loop re-checks the deadline
		}
		serverIP, ok := parseDHCPServer(buf[:n])
		if ok && !seen[serverIP] {
			seen[serverIP] = true
			log.Printf("[Discovery/DHCP] Observed DHCP server: %s", serverIP)
			rep.Add(DiscoveredService{
				ServiceType:   "dhcp",
				Host:          serverIP,
				Port:          67,
				DiscoveredVia: "passive_dhcp",
			})
		}
	}
}

// parseDHCPServer walks Ethernet -> IPv4 -> UDP -> DHCP and, if the
// packet is a DHCP server message (OFFER/ACK, i.e. BOOTREPLY from
// source port 67), returns the server's IP. Returns ok=false otherwise.
//
// Hand-rolled parsing (no gopacket) keeps the agent dependency-free; the
// layout is fixed and well-known, and every access is length-checked.
func parseDHCPServer(frame []byte) (string, bool) {
	// Ethernet header = 14 bytes; EtherType at [12:14] must be IPv4.
	if len(frame) < 14 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return "", false
	}
	ip := frame[14:]
	if len(ip) < 20 {
		return "", false
	}
	if ip[0]>>4 != 4 {
		return "", false // not IPv4
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return "", false
	}
	if ip[9] != 17 { // protocol 17 = UDP
		return "", false
	}
	srcIP := net.IP(ip[12:16]).String()

	udp := ip[ihl:]
	if len(udp) < 8 {
		return "", false
	}
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	// DHCP server speaks from port 67. A server->client message is
	// srcPort 67; we accept the 67<->68 pair either way but require the
	// server side to be 67.
	if srcPort != 67 {
		return "", false
	}
	_ = dstPort

	dhcp := udp[8:]
	// BOOTP/DHCP fixed header: op(1) at [0]; op=2 is BOOTREPLY (server).
	if len(dhcp) < 240 {
		return "", false
	}
	if dhcp[0] != 2 {
		return "", false // not a server reply
	}

	// Prefer the DHCP "Server Identifier" option (53? no - option 54) if
	// present, since siaddr can be 0. Options start after the 4-byte
	// magic cookie at offset 236..240.
	if serverID, ok := dhcpOption(dhcp[240:], 54); ok && len(serverID) == 4 {
		return net.IP(serverID).String(), true
	}
	// Fall back to the IP source address of the reply.
	return srcIP, true
}

// dhcpOption scans TLV-encoded DHCP options for the given code.
func dhcpOption(opts []byte, code byte) ([]byte, bool) {
	i := 0
	for i < len(opts) {
		c := opts[i]
		if c == 255 { // END
			break
		}
		if c == 0 { // PAD
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		length := int(opts[i+1])
		if i+2+length > len(opts) {
			break
		}
		if c == code {
			return opts[i+2 : i+2+length], true
		}
		i += 2 + length
	}
	return nil, false
}
