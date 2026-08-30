package controller

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ksahoo/fyke/internal/config"
)

func TestSecurityAcceptsForwardedHeadersFromContainerHostGateway(t *testing.T) {
	a := proxyTestAPI()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.24.0.1:43122"
	req.Header.Set("X-Forwarded-For", "100.64.0.10")
	recorder := httptest.NewRecorder()

	a.security(next).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}
}

func TestSecurityRejectsForwardedHeadersFromPeerContainer(t *testing.T) {
	a := proxyTestAPI()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.24.0.4:43122"
	req.Header.Set("X-Forwarded-For", "100.64.0.10")
	recorder := httptest.NewRecorder()

	a.security(next).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func proxyTestAPI() *API {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("172.24.0.3"), Mask: net.CIDRMask(16, 32)},
	}
	return &API{
		cfg: config.Config{Access: config.Access{TrustedProxies: []string{"127.0.0.1", "::1"}}},
		isTrustedLocalRequest: func(remoteAddr string) bool {
			host, _, err := net.SplitHostPort(remoteAddr)
			return err == nil && isDirectGateway(net.ParseIP(host), addrs)
		},
	}
}

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
