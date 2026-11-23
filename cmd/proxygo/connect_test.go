package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestParseConnectTarget(t *testing.T) {
	cfg := connectConfig{
		ports:        map[int]struct{}{443: {}},
		allowedHosts: []string{"example.com", "*.trusted.com"},
	}
	tests := []struct {
		name      string
		authority string
		wantHost  string
		wantPort  int
		wantErr   error
	}{
		{"exact host", "example.com:443", "example.com", 443, nil},
		{"normalizes host", "Example.COM.:443", "example.com", 443, nil},
		{"wildcard host", "api.trusted.com:443", "api.trusted.com", 443, nil},
		{"wildcard apex rejected", "trusted.com:443", "", 0, errConnectForbidden},
		{"port not allowed", "example.com:22", "", 0, errConnectForbidden},
		{"host not allowed", "other.com:443", "", 0, errConnectForbidden},
		{"missing port", "example.com", "", 0, errConnectBadRequest},
		{"userinfo", "user@example.com:443", "", 0, errConnectBadRequest},
		{"unbracketed IPv6", "::1:443", "", 0, errConnectBadRequest},
		{"port out of range", "example.com:70000", "", 0, errConnectBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, port, err := parseConnectTarget(test.authority, cfg)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if host != test.wantHost || port != test.wantPort {
				t.Fatalf("got %s:%d, want %s:%d", host, port, test.wantHost, test.wantPort)
			}
		})
	}
}

func TestHostAllowed(t *testing.T) {
	allowed := []string{"example.com", "*.trusted.com"}
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"api.trusted.com", true},
		{"deep.api.trusted.com", true},
		{"trusted.com", false},
		{"badexample.com", false},
		{"other.com", false},
	}
	for _, test := range tests {
		if got := hostAllowed(test.host, allowed); got != test.want {
			t.Errorf("hostAllowed(%q) = %v, want %v", test.host, got, test.want)
		}
	}
	if !hostAllowed("anything.example", []string{"*"}) {
		t.Fatal("wildcard * did not allow a host")
	}
}

func TestIsPublicAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"::ffff:8.8.8.8", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false},
		{"100.64.0.1", false},
		{"0.0.0.0", false},
		{"192.0.2.1", false},
		{"192.88.99.1", false},
		{"::1", false},
		{"64:ff9b::7f00:1", false},
		{"2001:2::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"2001:db8::1", false},
		{"2002:7f00:1::", false},
		{"2606:4700:4700::1111", true},
	}
	for _, test := range tests {
		addr := netip.MustParseAddr(test.addr)
		if got := isPublicAddr(addr); got != test.want {
			t.Errorf("isPublicAddr(%s) = %v, want %v", test.addr, got, test.want)
		}
	}
}

func TestResolvePublicRejectsBlockedIPDestinations(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "ff02::1"} {
		t.Run(host, func(t *testing.T) {
			if _, err := resolvePublic(context.Background(), host); !errors.Is(err, errBlockedAddress) {
				t.Fatalf("resolvePublic(%q) error = %v, want blocked-address error", host, err)
			}
		})
	}
}

func TestResolvePublicRejectsPrivateDNSAnswers(t *testing.T) {
	tests := []struct {
		name      string
		addresses []netip.Addr
	}{
		{name: "private", addresses: []netip.Addr{netip.MustParseAddr("10.1.2.3")}},
		{name: "link-local", addresses: []netip.Addr{netip.MustParseAddr("169.254.10.20")}},
		{name: "multicast", addresses: []netip.Addr{netip.MustParseAddr("239.1.2.3")}},
		{name: "mixed public and private", addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("192.168.1.5")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lookup := func(context.Context, string) ([]netip.Addr, error) {
				return test.addresses, nil
			}
			if _, err := resolvePublicWithLookup(context.Background(), "origin.proxygo.test", lookup); !errors.Is(err, errBlockedAddress) {
				t.Fatalf("private DNS answer error = %v, want blocked-address error", err)
			}
		})
	}
}

func TestPrivateNetworkResolutionPolicy(t *testing.T) {
	privateAddress := netip.MustParseAddr("192.168.10.20")
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{privateAddress}, nil
	}
	if _, err := resolvePublicWithPolicy(context.Background(), "origin.proxygo.test", lookup, true); !errors.Is(err, errBlockedAddress) {
		t.Fatalf("private address with blocking enabled: error = %v, want blocked-address error", err)
	}
	if addresses, err := resolvePublicWithPolicy(context.Background(), "origin.proxygo.test", lookup, false); err != nil || len(addresses) != 1 || addresses[0] != privateAddress {
		t.Fatalf("private address with blocking disabled: addresses=%v error=%v", addresses, err)
	}
	for _, blockPrivateNetwork := range []bool{true, false} {
		core := &proxyCore{blockPrivateNetwork: blockPrivateNetwork}
		handler := newConnectHandler(nil, core, connectConfig{maxTunnels: 1}, nil)
		_, err := handler.resolve(context.Background(), privateAddress.String())
		if blockPrivateNetwork && !errors.Is(err, errBlockedAddress) {
			t.Errorf("core policy true returned %v, want blocked-address error", err)
		}
		if !blockPrivateNetwork && err != nil {
			t.Errorf("core policy false rejected private destination: %v", err)
		}
	}
}

func TestConnectHandlerRejectsBadTargets(t *testing.T) {
	cfg := connectConfig{
		ports:        map[int]struct{}{443: {}},
		allowedHosts: []string{"example.com"},
		maxTunnels:   1,
	}
	handler := newConnectHandler(nil, nil, cfg, log.New(io.Discard, "", 0))
	tests := []struct {
		authority string
		want      int
	}{
		{"example.com:22", http.StatusForbidden},
		{"other.com:443", http.StatusForbidden},
		{"example.com", http.StatusBadRequest},
	}
	for _, test := range tests {
		request := httptest.NewRequest(http.MethodConnect, "http://"+test.authority, nil)
		request.Host = test.authority
		recorder := httptest.NewRecorder()
		handler.serve(recorder, request)
		if recorder.Code != test.want {
			t.Errorf("CONNECT %s = %d, want %d", test.authority, recorder.Code, test.want)
		}
	}
}

func TestConnectHandlerRejectsBlockedAddress(t *testing.T) {
	cfg := connectConfig{
		ports:        map[int]struct{}{443: {}},
		allowedHosts: []string{"example.com"},
		maxTunnels:   1,
	}
	handler := newConnectHandler(nil, nil, cfg, log.New(io.Discard, "", 0))
	handler.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return nil, fmt.Errorf("%w: 10.0.0.1", errBlockedAddress)
	}
	request := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	request.Host = "example.com:443"
	recorder := httptest.NewRecorder()
	handler.serve(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("blocked address = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestConnectHandlerRejectsBlockedDestinations(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		lookup func(context.Context, string) ([]netip.Addr, error)
	}{
		{name: "loopback", host: "127.0.0.1"},
		{name: "private", host: "10.20.30.40"},
		{name: "link-local", host: "169.254.10.20"},
		{name: "multicast", host: "239.1.2.3"},
		{
			name: "hostname resolving private",
			host: "internal.proxygo.test",
			lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
				return resolvePublicWithLookup(ctx, host, func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("192.168.10.20")}, nil
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := connectConfig{
				ports:        map[int]struct{}{443: {}},
				allowedHosts: []string{"*"},
				maxTunnels:   1,
				resolve:      test.lookup,
			}
			handler := newConnectHandler(nil, nil, cfg, log.New(io.Discard, "", 0))
			authority := net.JoinHostPort(test.host, "443")
			request := httptest.NewRequest(http.MethodConnect, "http://"+authority, nil)
			request.Host = authority
			recorder := httptest.NewRecorder()
			handler.serve(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("CONNECT to blocked %s destination = %d, want 403", test.name, recorder.Code)
			}
		})
	}
}

func TestConnectHandlerLimitsTunnels(t *testing.T) {
	cfg := connectConfig{
		ports:        map[int]struct{}{443: {}},
		allowedHosts: []string{"example.com"},
		maxTunnels:   1,
	}
	handler := newConnectHandler(nil, nil, cfg, log.New(io.Discard, "", 0))
	handler.sem <- struct{}{}
	defer func() { <-handler.sem }()

	request := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	request.Host = "example.com:443"
	recorder := httptest.NewRecorder()
	handler.serve(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("full tunnel limit = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}

func TestConfiguredConnectConfigRequiresAllowlist(t *testing.T) {
	t.Setenv("PROXYGO_CONNECT_PORTS", "443")
	t.Setenv("PROXYGO_CONNECT_MAX", "4")
	t.Setenv("PROXYGO_CONNECT_ALLOWED_HOSTS", "")
	t.Setenv("PROXYGO_CA_DIR", t.TempDir())
	t.Setenv("PROXYGO_CA_ORG", "Test Org")
	if _, err := configuredConnectConfig(); err == nil {
		t.Fatal("empty allowlist was accepted")
	}
}

func TestConnectHandlerNonExistentDomain(t *testing.T) {
	cfg := connectConfig{
		ports:        map[int]struct{}{443: {}},
		allowedHosts: []string{"example.com"},
		maxTunnels:   1,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return nil, fmt.Errorf("no such host")
		},
	}
	handler := newConnectHandler(nil, nil, cfg, log.New(io.Discard, "", 0))
	request := httptest.NewRequest(http.MethodConnect, "http://nonexistent.example.com:443", nil)
	request.Host = "nonexistent.example.com:443"
	recorder := httptest.NewRecorder()
	handler.serve(recorder, request)
	// Unknown host not in allowlist -> Forbidden
	if recorder.Code != http.StatusForbidden {
		t.Errorf("non-existent domain = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestConnectHandlerInvalidCert(t *testing.T) {
	// Test that certificate generation works with a valid CA
	caDir := filepath.Join(t.TempDir(), "ca")
	ca, err := newCertAuthority(caDir, "Test Org")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.certificateForHost("example.com")
	if err != nil {
		t.Fatalf("certificateForHost failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	// Verify certificate has proper SAN
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Fatalf("expected DNS SAN example.com, got %v", leaf.DNSNames)
	}
}

func TestConnectHandlerConcurrentConnections(t *testing.T) {
	cfg := connectConfig{
		ports:        map[int]struct{}{443: {}},
		allowedHosts: []string{"example.com"},
		maxTunnels:   2,
	}
	handler := newConnectHandler(nil, nil, cfg, log.New(io.Discard, "", 0))
	// Acquire both tunnel slots
	handler.sem <- struct{}{}
	handler.sem <- struct{}{}
	defer func() { <-handler.sem; <-handler.sem }()

	request := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	request.Host = "example.com:443"
	recorder := httptest.NewRecorder()
	handler.serve(recorder, request)
	// Third connection should be rejected (too many tunnels)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("third concurrent connection = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}
