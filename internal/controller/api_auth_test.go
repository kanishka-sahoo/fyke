package controller

import (
	"net"
	"testing"
)

func TestIsDirectGateway(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("172.24.0.3"), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.ParseIP("10.8.0.9"), Mask: net.CIDRMask(24, 32)},
	}
	for _, test := range []struct {
		name string
		ip   string
		want bool
	}{
		{name: "first gateway", ip: "172.24.0.1", want: true},
		{name: "second gateway", ip: "10.8.0.1", want: true},
		{name: "peer container", ip: "172.24.0.4", want: false},
		{name: "outside subnet", ip: "192.168.1.1", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isDirectGateway(net.ParseIP(test.ip), addrs); got != test.want {
				t.Fatalf("isDirectGateway(%s) = %v, want %v", test.ip, got, test.want)
			}
		})
	}
}
