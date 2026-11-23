package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
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
	"sync"
	"sync/atomic"
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

const mitmTestHost = "origin.proxygo.test"

type mitmFixture struct {
	client       *http.Client
	proxyURL     *url.URL
	originURL    string
	proxyCA      *certAuthority
	proxyRoots   *x509.CertPool
	core         *proxyCore
	connect      *connectHandler
	logOutput    *bytes.Buffer
	originCalls  atomic.Int64
	activeOrigin atomic.Int32
	maxOrigin    atomic.Int32
}

func newMITMFixture(t *testing.T, enginePolicy FailurePolicy, mode inspectionMode, engineAvailable bool) *mitmFixture {
	t.Helper()
	fixture := &mitmFixture{logOutput: &bytes.Buffer{}}
	logger := log.New(fixture.logOutput, "", 0)

	originCA := newTestCA(t)
	originCertificate, err := originCA.certificateForHost(mitmTestHost)
	if err != nil {
		t.Fatal(err)
	}
	originRoots := x509.NewCertPool()
	originRoots.AddCert(originCA.cert)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.originCalls.Add(1)
		active := fixture.activeOrigin.Add(1)
		for previous := fixture.maxOrigin.Load(); active > previous && !fixture.maxOrigin.CompareAndSwap(previous, active); previous = fixture.maxOrigin.Load() {
		}
		defer fixture.activeOrigin.Add(-1)
		time.Sleep(5 * time.Millisecond)
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/secret" {
			_, _ = w.Write([]byte("response SECRET hidden"))
			return
		}
		_, _ = w.Write([]byte("ORIGIN:" + string(body)))
	}))
	origin.TLS = &tls.Config{
		Certificates: []tls.Certificate{*originCertificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	origin.StartTLS()
	t.Cleanup(origin.Close)

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	originPort, err := strconv.Atoi(originURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	originIP, err := netip.ParseAddr(originURL.Hostname())
	if err != nil {
		t.Fatal(err)
	}

	fixture.proxyCA = newTestCA(t)
	fixture.proxyRoots = x509.NewCertPool()
	fixture.proxyRoots.AddCert(fixture.proxyCA.cert)
	engineSocket := filepath.Join(t.TempDir(), "engine.sock")
	if engineAvailable {
		engineSocket = startFakeEngine(t)
	}
	fixture.core = &proxyCore{
		engine:             newUDSClientWithTimeout(engineSocket, enginePolicy, 2*time.Second, logger),
		modes:              newActiveMode(mode),
		events:             newEventHub(),
		securityPolicy:     BlockUninspected,
		inspectRequests:    true,
		inspectResponses:   true,
		inspectHeadersFlag: true,
		maxBodyBytes:       1 << 20,
	}
	fixture.connect = newConnectHandler(fixture.proxyCA, fixture.core, connectConfig{
		ports:        map[int]struct{}{originPort: {}},
		allowedHosts: []string{mitmTestHost},
		maxTunnels:   32,
		resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{originIP}, nil
		},
	}, logger)
	fixture.connect.originRootCAs = originRoots

	proxyServer := newHTTPProxy(fixture.core, fixture.connect, "127.0.0.1:0")
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxyServer.Serve(proxyListener) }()
	t.Cleanup(func() {
		fixture.connect.closeAll()
		_ = proxyServer.Close()
	})
	fixture.proxyURL, err = url.Parse("http://" + proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	fixture.originURL = fmt.Sprintf("https://%s:%d", mitmTestHost, originPort)
	fixture.client = fixture.newClient("")
	t.Cleanup(fixture.client.CloseIdleConnections)
	return fixture
}

func (f *mitmFixture) newClient(serverName string) *http.Client {
	tlsConfig := &tls.Config{RootCAs: f.proxyRoots, MinVersion: tls.VersionTLS12}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(f.proxyURL),
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: false,
		MaxConnsPerHost:   32,
	}, Timeout: 5 * time.Second}
}

func readMITMResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(body)
}

func (f *mitmFixture) requireEvent(t *testing.T, path, direction, status string) inspectionEvent {
	t.Helper()
	for _, event := range f.core.events.snapshot(string(f.core.modes.current())).Events {
		if event.Path == path && event.ConnectionType == direction && event.Status == status &&
			(direction == "connect" || event.Direction == strings.ToUpper(direction)) {
			if event.Protocol != "HTTPS" || (direction != "connect" && !event.Inspected) {
				t.Fatalf("event %s/%s/%s not marked as inspected HTTPS: %#v", path, direction, status, event)
			}
			return event
		}
	}
	t.Fatalf("missing HTTPS inspection event path=%s direction=%s status=%s", path, direction, status)
	return inspectionEvent{}
}

func TestMITMTunnelModesAndInspection(t *testing.T) {
	fixture := newMITMFixture(t, FailOpen, modeMonitor, true)
	secretRequest := "request SECRET marker"

	response, err := fixture.client.Post(fixture.originURL+"/echo", "text/plain", strings.NewReader(secretRequest))
	if err != nil {
		t.Fatalf("MONITOR POST through CONNECT: %v", err)
	}
	if got, want := readMITMResponse(t, response), "ORIGIN:"+secretRequest; got != want {
		t.Fatalf("MONITOR forwarded body = %q, want %q", got, want)
	}
	if event := fixture.requireEvent(t, "/echo", "request", "passed"); len(event.Findings) == 0 {
		t.Fatal("MONITOR request did not report the detected secret")
	}
	if event := fixture.requireEvent(t, "/echo", "response", "passed"); len(event.Findings) == 0 {
		t.Fatal("MONITOR response did not report the echoed secret")
	}
	if event := fixture.requireEvent(t, "", "connect", "cert_generated"); !event.CertGenerated {
		t.Fatal("CONNECT certificate-generation event is missing its certificate marker")
	}
	fixture.requireEvent(t, "", "connect", "tls_established")

	fixture.core.modes.set(modeSanitize)
	response, err = fixture.client.Post(fixture.originURL+"/echo", "text/plain", strings.NewReader(secretRequest))
	if err != nil {
		t.Fatalf("SANITIZE POST through CONNECT: %v", err)
	}
	if got, want := readMITMResponse(t, response), "ORIGIN:request [REDACTED] marker"; got != want {
		t.Fatalf("SANITIZE forwarded body = %q, want %q", got, want)
	}
	if event := fixture.requireEvent(t, "/echo", "request", "sanitized"); len(event.Findings) == 0 {
		t.Fatal("SANITIZE request did not retain the secret finding")
	}

	response, err = fixture.client.Get(fixture.originURL + "/secret")
	if err != nil {
		t.Fatalf("SANITIZE GET response: %v", err)
	}
	if got, want := readMITMResponse(t, response), "response [REDACTED] hidden"; got != want {
		t.Fatalf("SANITIZE response = %q, want %q", got, want)
	}
	if event := fixture.requireEvent(t, "/secret", "response", "sanitized"); len(event.Findings) == 0 {
		t.Fatal("SANITIZE response did not retain the secret finding")
	}

	fixture.core.modes.set(modeBlock)
	originCalls := fixture.originCalls.Load()
	response, err = fixture.client.Post(fixture.originURL+"/echo", "text/plain", strings.NewReader(secretRequest))
	if err != nil {
		t.Fatalf("BLOCK POST response: %v", err)
	}
	if got := readMITMResponse(t, response); response.StatusCode != http.StatusForbidden || !strings.Contains(got, "blocked") {
		t.Fatalf("BLOCK request response = %d %q", response.StatusCode, got)
	}
	if fixture.originCalls.Load() != originCalls {
		t.Fatal("BLOCK forwarded the secret request to the HTTPS origin")
	}

	response, err = fixture.client.Get(fixture.originURL + "/secret")
	if err != nil {
		t.Fatalf("BLOCK GET response: %v", err)
	}
	if got := readMITMResponse(t, response); response.StatusCode != http.StatusForbidden || !strings.Contains(got, "blocked") {
		t.Fatalf("BLOCK response body = %d %q", response.StatusCode, got)
	}
	fixture.requireEvent(t, "/secret", "response", "blocked")
}

func TestMITMRejectsMismatchedSNI(t *testing.T) {
	fixture := newMITMFixture(t, FailOpen, modeMonitor, true)
	client := fixture.newClient("attacker.proxygo.test")
	defer client.CloseIdleConnections()
	response, err := client.Get(fixture.originURL + "/plain")
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("CONNECT with a mismatched TLS SNI unexpectedly succeeded")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, event := range fixture.core.events.snapshot(string(modeMonitor)).Events {
			if event.ConnectionType == "connect" && event.Status == "tls_error" {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("TLS SNI mismatch was not recorded as a TLS error")
}

func TestMITMDNSResolutionIsPinnedForConnection(t *testing.T) {
	fixture := newMITMFixture(t, FailOpen, modeMonitor, true)
	var lookups atomic.Int32
	fixture.connect.resolve = func(context.Context, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}
	response, err := fixture.client.Get(fixture.originURL + "/plain")
	if err != nil {
		t.Fatalf("request failed after the resolver's later answer changed: %v", err)
	}
	if got := readMITMResponse(t, response); got != "ORIGIN:" {
		t.Fatalf("response = %q, want ORIGIN:", got)
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("destination was resolved %d times, want exactly once", got)
	}
}

func TestMITMEngineUnavailablePoliciesDoNotLogRequestBody(t *testing.T) {
	const sensitiveBody = "SECRET_VALUE_DO_NOT_LOG"
	for _, test := range []struct {
		name   string
		policy FailurePolicy
		status int
		body   string
	}{
		{name: "fail open", policy: FailOpen, status: http.StatusOK, body: "ORIGIN:" + sensitiveBody},
		{name: "fail closed", policy: FailClosed, status: http.StatusServiceUnavailable, body: "request blocked"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMITMFixture(t, test.policy, modeMonitor, false)
			response, err := fixture.client.Post(fixture.originURL+"/echo", "text/plain", strings.NewReader(sensitiveBody))
			if err != nil {
				t.Fatalf("request with unavailable engine: %v", err)
			}
			if got := readMITMResponse(t, response); response.StatusCode != test.status || !strings.Contains(got, test.body) {
				t.Fatalf("engine-unavailable response = %d %q, want status %d and %q", response.StatusCode, got, test.status, test.body)
			}
			if strings.Contains(fixture.logOutput.String(), sensitiveBody) {
				t.Fatal("engine error logs exposed the request body")
			}
		})
	}
}

func TestMITMRejectsUntrustedOriginCertificateWithoutLoggingBody(t *testing.T) {
	fixture := newMITMFixture(t, FailOpen, modeMonitor, true)
	fixture.connect.originRootCAs = x509.NewCertPool()
	const sensitiveBody = "SECRET_VALUE_DO_NOT_LOG"
	response, err := fixture.client.Post(fixture.originURL+"/echo", "text/plain", strings.NewReader(sensitiveBody))
	if err != nil {
		t.Fatalf("request result: %v", err)
	}
	if got := readMITMResponse(t, response); response.StatusCode != http.StatusBadGateway || !strings.Contains(got, "upstream unavailable") {
		t.Fatalf("invalid origin certificate response = %d %q", response.StatusCode, got)
	}
	if strings.Contains(fixture.logOutput.String(), sensitiveBody) {
		t.Fatal("TLS error logs exposed the request body")
	}
	if !strings.Contains(fixture.logOutput.String(), "certificate") {
		t.Fatalf("TLS validation failure was not logged: %s", fixture.logOutput.String())
	}
}

func TestMITMConcurrentTunnelsCloseCleanly(t *testing.T) {
	fixture := newMITMFixture(t, FailOpen, modeMonitor, true)
	const count = 12
	clients := make([]*http.Client, count)
	var wait sync.WaitGroup
	errors := make(chan error, count)
	for index := 0; index < count; index++ {
		clients[index] = fixture.newClient("")
		wait.Add(1)
		go func(client *http.Client) {
			defer wait.Done()
			response, err := client.Get(fixture.originURL + "/plain")
			if err != nil {
				errors <- err
				return
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				errors <- readErr
				return
			}
			if response.StatusCode != http.StatusOK || string(body) != "ORIGIN:" {
				errors <- fmt.Errorf("unexpected concurrent response: %d %q", response.StatusCode, body)
			}
		}(clients[index])
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if got := fixture.maxOrigin.Load(); got < 2 {
		t.Fatalf("origin saw max concurrency %d, want at least 2", got)
	}

	fixture.connect.closeAll()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fixture.connect.mu.Lock()
		remaining := len(fixture.connect.tunnels)
		fixture.connect.mu.Unlock()
		if remaining == 0 {
			for _, client := range clients {
				client.CloseIdleConnections()
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("CONNECT tunnels remained tracked after closeAll")
}
