package discovery

import (
	"log"
	"sync"
	"syscall"
)

// hasRawSocketCapability reports whether this process can actually open a
// raw packet socket - i.e. whether it effectively holds CAP_NET_RAW.
//
// Rather than guessing from uid==0 (wrong: a non-root process can be
// granted CAP_NET_RAW via file capabilities, and a root process can have
// it stripped), this PROBES the real capability the way the privileged
// methods will use it: try to open an AF_PACKET raw socket and
// immediately close it. If that succeeds, the raw-socket discovery
// methods (ARP scan, passive DHCP sniff) can run; if it fails with
// EPERM, they're quietly skipped.
//
// The result is cached: the capability doesn't change during the
// process's lifetime, and probing opens a real socket each time.
var (
	rawCapOnce   sync.Once
	rawCapResult bool
)

func hasRawSocketCapability() bool {
	rawCapOnce.Do(func() {
		// AF_PACKET + SOCK_RAW is the Linux raw-link-layer socket the
		// ARP/DHCP sniffers need. Opening it requires CAP_NET_RAW.
		// htons(ETH_P_ALL) = 0x0300 in network byte order; we don't even
		// need to receive anything, just prove we're allowed to open it.
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
		if err != nil {
			rawCapResult = false
			return
		}
		_ = syscall.Close(fd)
		rawCapResult = true
	})
	return rawCapResult
}

// logCapabilityStatus prints, once at startup, which method tiers are
// available - so an operator can immediately see from the logs whether
// the agent is running privileged (and thus doing full discovery) or
// unprivileged (SRV/DNS/mDNS/LLMNR only).
func logCapabilityStatus() {
	if hasRawSocketCapability() {
		log.Printf("[Discovery] CAP_NET_RAW available - raw-socket methods (ARP scan, passive DHCP) will run")
	} else {
		log.Printf("[Discovery] No CAP_NET_RAW - running unprivileged methods only " +
			"(DNS SRV, resolv.conf, gateway, mDNS, LLMNR). To enable ARP/DHCP discovery, " +
			"grant the agent CAP_NET_RAW.")
	}
}
