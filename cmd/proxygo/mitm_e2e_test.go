package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func startFakeEngine(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "engine.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					var req InspectionRequest
					if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
						continue
					}
					body := req.Body
					var findings []Finding
					if strings.Contains(body, "SECRET") {
						body = strings.ReplaceAll(body, "SECRET", "[REDACTED]")
						findings = append(findings, Finding{Kind: "TEST_SECRET", Path: "$"})
					}
					response := InspectionResponse{
						ID:            req.ID,
						Category:      "GENERIC_JSON",
						RiskLevel:     "LOW",
						Findings:      findings,
						SanitizedBody: body,
					}
					data, err := json.Marshal(response)
					if err != nil {
						return
					}
					if _, err := c.Write(append(data, '\n')); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return sock
}

func TestMITMTunnelEndToEnd(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/secret" {
			_, _ = w.Write([]byte("response SECRET hidden"))
			return
		}
		_, _ = w.Write([]byte("ORIGIN:" + string(body)))
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	originPort, err := strconv.Atoi(originURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	originHost := originURL.Hostname()

	ca, err := newCertAuthority(filepath.Join(t.TempDir(), "ca"), "Test Org")
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)
	originPool := x509.NewCertPool()
	originPool.AddCert(origin.Certificate())

	core := &proxyCore{
		engine:             newUDSClientWithTimeout(startFakeEngine(t), FailOpen, 2*time.Second, log.New(io.Discard, "", 0)),
		modes:              newActiveMode(modeMonitor),
		events:             newEventHub(),
		inspectRequests:    true,
		inspectResponses:   true,
		inspectHeadersFlag: true,
		maxBodyBytes:       1 << 20,
	}
	cfg := connectConfig{
		ports:        map[int]struct{}{originPort: {}},
		allowedHosts: []string{originHost},
		maxTunnels:   8,
		resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(originHost)}, nil
		},
	}
	connect := newConnectHandler(ca, core, cfg, log.New(io.Discard, "", 0))
	connect.originRootCAs = originPool

	proxyServer := newHTTPProxy(core, connect, "127.0.0.1:0")
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxyServer.Serve(proxyLn) }()
	defer proxyServer.Close()

	proxyURL, err := url.Parse("http://" + proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}}
	defer client.CloseIdleConnections()

	readBody := func(resp *http.Response) string {
		t.Helper()
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		return string(data)
	}

	core.modes.set(modeMonitor)
	resp, err := client.Get(origin.URL + "/plain")
	if err != nil {
		t.Fatalf("MONITOR GET: %v", err)
	}
	if got := readBody(resp); got != "ORIGIN:" {
		t.Fatalf("MONITOR GET body = %q, want %q", got, "ORIGIN:")
	}

	resp, err = client.Post(origin.URL+"/plain", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("MONITOR POST: %v", err)
	}
	if got := readBody(resp); got != "ORIGIN:payload" {
		t.Fatalf("MONITOR POST body = %q, want %q", got, "ORIGIN:payload")
	}

	core.modes.set(modeSanitize)
	resp, err = client.Get(origin.URL + "/secret")
	if err != nil {
		t.Fatalf("SANITIZE GET: %v", err)
	}
	if got := readBody(resp); got != "response [REDACTED] hidden" {
		t.Fatalf("SANITIZE GET body = %q, want %q", got, "response [REDACTED] hidden")
	}
}
