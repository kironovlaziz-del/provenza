package discovery

import (
	"net"
	"reflect"
	"testing"
)

func ips(s ...string) []net.IP {
	var out []net.IP
	for _, x := range s {
		out = append(out, net.ParseIP(x))
	}
	return out
}

var machine = []adapterInfo{
	{Name: "Loopback Pseudo-Interface 1", Up: true, Loopback: true, Metric: 75, DNS: ips("127.0.0.1")},
	{Name: "Wi-Fi", Up: true, Metric: 50, DNS: ips("192.168.1.1", "fec0:0:0:ffff::1", "fec0:0:0:ffff::2"),
		Gateways: ips("192.168.1.1"), Suffixes: []string{"home.lan"}},
	{Name: "Ethernet", Up: true, Metric: 25, DNS: ips("10.0.0.2", "192.168.1.1", "fe80::1"),
		Gateways: ips("fe80::abcd", "10.0.0.1"), Suffixes: []string{"corp.example.com", "corp.example.com"}},
	{Name: "Disconnected", Up: false, Metric: 5, DNS: ips("172.16.0.9"), Gateways: ips("172.16.0.1"), Suffixes: []string{"old.lan"}},
}

func TestDNSFromAdapters(t *testing.T) {
	// the preferred adapter's servers first, each once; the placeholders, the
	// link-local and loopback ones and the adapter that is down are not servers
	want := []string{"10.0.0.2", "192.168.1.1"}
	if got := dnsFromAdapters(machine); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestGatewayFromAdapters(t *testing.T) {
	ip, name := gatewayFromAdapters(machine)
	if ip.String() != "10.0.0.1" || name != "Ethernet" { // IPv4 before IPv6, lowest metric, never the disconnected one
		t.Fatalf("got %v on %q", ip, name)
	}
	// only an IPv6 gateway: that one
	ip, name = gatewayFromAdapters([]adapterInfo{{Name: "Wi-Fi", Up: true, Gateways: ips("2001:db8::1")}})
	if ip.String() != "2001:db8::1" || name != "Wi-Fi" {
		t.Fatalf("got %v on %q", ip, name)
	}
	// none
	if ip, _ := gatewayFromAdapters([]adapterInfo{{Name: "x", Up: true}, {Name: "y", Gateways: ips("10.0.0.1")}}); ip != nil {
		t.Fatalf("got %v", ip)
	}
	if ip, _ := gatewayFromAdapters(nil); ip != nil {
		t.Fatalf("got %v", ip)
	}
}

func TestSuffixesFromAdapters(t *testing.T) {
	got := suffixesFromAdapters(machine)
	want := []string{"corp.example.com", "corp.example.com", "home.lan"} // the caller deduplicates
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestUsableDNS(t *testing.T) {
	for s, want := range map[string]bool{
		"8.8.8.8": true, "10.1.2.3": true, "2606:4700:4700::1111": true, "fd00::53": true,
		"127.0.0.1": false, "::1": false, "0.0.0.0": false, "169.254.1.1": false, "fe80::1": false,
		"fec0:0:0:ffff::1": false, "fec0::5": false,
	} {
		if got := usableDNS(net.ParseIP(s)); got != want {
			t.Errorf("usableDNS(%s) = %v, want %v", s, got, want)
		}
	}
	if usableDNS(nil) {
		t.Error("nil")
	}
}
