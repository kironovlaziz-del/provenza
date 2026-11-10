//go:build windows

package discovery

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ifOperStatusUp   = 1
	ifTypeLoopback   = 24
	maxAdapterBuffer = 1 << 20
)

// adapters reads the network settings of the machine: GetAdaptersAddresses,
// with the DNS servers, gateways and DNS suffixes of each adapter. A
// local read of the settings Windows keeps; nothing is sent.
func adapters() []adapterInfo {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_UNICAST
	size := uint32(15 * 1024) // the documented starting size
	var buf []byte
	for try := 0; try < 4; try++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size == 0 || size > maxAdapterBuffer {
			return nil
		}
		buf = nil
	}
	if buf == nil {
		return nil
	}
	var out []adapterInfo
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		info := adapterInfo{
			Name:     windows.UTF16PtrToString(a.FriendlyName),
			Up:       a.OperStatus == ifOperStatusUp,
			Loopback: a.IfType == ifTypeLoopback,
			Metric:   a.Ipv4Metric,
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := d.Address.IP(); ip != nil {
				info.DNS = append(info.DNS, ip)
			}
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil {
				info.Gateways = append(info.Gateways, ip)
			}
		}
		if s := windows.UTF16PtrToString(a.DnsSuffix); s != "" {
			info.Suffixes = append(info.Suffixes, s)
		}
		for s := a.FirstDnsSuffix; s != nil; s = s.Next {
			if v := windows.UTF16ToString(s.String[:]); v != "" {
				info.Suffixes = append(info.Suffixes, v)
			}
		}
		out = append(out, info)
	}
	return out
}

// dnsServerAddresses: the DNS servers of the adapters that are up ("adapter_config").
func dnsServerAddresses() ([]string, string) {
	return dnsFromAdapters(adapters()), "adapter_config"
}

// defaultGateway: the gateway of the preferred adapter ("adapter_config").
func defaultGateway() (net.IP, string, string) {
	ip, name := gatewayFromAdapters(adapters())
	return ip, name, "adapter_config"
}

// resolverSearchDomains: the DNS suffixes of the adapters that are up.
func resolverSearchDomains() []string { return suffixesFromAdapters(adapters()) }
