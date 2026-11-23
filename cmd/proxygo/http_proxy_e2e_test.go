package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testAnthropicKey = "sk-ant-api03-abcdefghijklmnopqrstuvwx"

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (body *closeTrackingBody) Close() error {
	body.closed = true
	return nil
}

func newPlainHTTPProxyClient(t *testing.T, core *proxyCore) *http.Client {
	t.Helper()
	proxy := httptest.NewServer(newHTTPProxy(core, nil, "").Handler)
	t.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 3 * time.Second}
}

func newHTTPProxyTestCore(t *testing.T, mode inspectionMode, maxBodyBytes int64) *proxyCore {
	t.Helper()
	return &proxyCore{
		engine:             newUDSClientWithTimeout(startFakeEngine(t), FailClosed, time.Second, log.New(io.Discard, "", 0)),
		modes:              newActiveMode(mode),
		events:             newEventHub(),
		securityPolicy:     BlockUninspected,
		inspectRequests:    true,
		inspectResponses:   true,
		inspectHeadersFlag: true,
		maxBodyBytes:       maxBodyBytes,
	}
}

func TestSetResponseBodyClosesReplacedBody(t *testing.T) {
	originalBody := &closeTrackingBody{Reader: strings.NewReader("original")}
	response := &http.Response{Header: make(http.Header), Body: originalBody}
	setResponseBody(response, []byte("blocked"))
	if !originalBody.closed {
		t.Fatal("original response body was not closed")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if string(body) != "blocked" {
		t.Fatalf("replacement response body = %q, want blocked", body)
	}
}

func TestPlainHTTPProxySanitizesEngineHeadersOnBothDirections(t *testing.T) {
	gotRequestHeader := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestHeader <- r.Header.Get("X-API-Key")
		w.Header().Set("X-API-Key", testAnthropicKey)
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	core := newHTTPProxyTestCore(t, modeSanitize, 1024)
	client := newPlainHTTPProxyClient(t, core)
	request, err := http.NewRequest(http.MethodGet, origin.URL+"/headers", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-API-Key", testAnthropicKey)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := <-gotRequestHeader; got != "[REDACTED_ANTHROPIC_KEY]" {
		t.Fatalf("origin received X-API-Key %q, want redacted value", got)
	}
	if got := response.Header.Get("X-API-Key"); got != "[REDACTED_ANTHROPIC_KEY]" {
		t.Fatalf("client received X-API-Key %q, want redacted value", got)
	}
	responseEvents := 0
	for _, event := range core.events.snapshot(string(modeSanitize)).Events {
		if event.ConnectionType == "response" {
			responseEvents++
			if event.Protocol != "HTTP" || !event.Inspected || event.Status != "sanitized" {
				t.Fatalf("plain HTTP response event = %#v", event)
			}
		}
	}
	if responseEvents != 1 {
		t.Fatalf("plain HTTP response inspection events = %d, want exactly one", responseEvents)
	}
}

func TestPlainHTTPProxyPreservesSanitizedMultipleHeaderValues(t *testing.T) {
	gotRequestHeaders := make(chan []string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestHeaders <- r.Header.Values("X-API-Key")
		w.Header().Add("X-API-Key", testAnthropicKey)
		w.Header().Add("X-API-Key", "safe-response-value")
	}))
	defer origin.Close()

	core := newHTTPProxyTestCore(t, modeSanitize, 1024)
	client := newPlainHTTPProxyClient(t, core)
	request, err := http.NewRequest(http.MethodGet, origin.URL+"/headers", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("X-API-Key", testAnthropicKey)
	request.Header.Add("X-API-Key", "safe-request-value")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got, want := <-gotRequestHeaders, []string{"[REDACTED_ANTHROPIC_KEY]", "safe-request-value"}; !equalStrings(got, want) {
		t.Fatalf("origin received X-API-Key values %q, want %q", got, want)
	}
	if got, want := response.Header.Values("X-API-Key"), []string{"[REDACTED_ANTHROPIC_KEY]", "safe-response-value"}; !equalStrings(got, want) {
		t.Fatalf("client received X-API-Key values %q, want %q", got, want)
	}
}

func TestPlainHTTPProxyPreservesExactOriginPathAndQuery(t *testing.T) {
	gotRequestURI := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI <- r.URL.RequestURI()
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	core := newHTTPProxyTestCore(t, modeMonitor, 1024)
	client := newPlainHTTPProxyClient(t, core)
	request, err := http.NewRequest(http.MethodGet, origin.URL+"/exact/path?first=one&second=two", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if got, want := <-gotRequestURI, "/exact/path?first=one&second=two"; got != want {
		t.Fatalf("origin request URI = %q, want %q", got, want)
	}
}

func TestPlainHTTPProxyFailClosedResponseUses503(t *testing.T) {
	socketPath := shortTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		reader := bufio.NewReader(connection)
		line, readErr := reader.ReadString('\n')
		if readErr == nil {
			var request InspectionRequest
			if json.Unmarshal([]byte(line), &request) == nil {
				payload, _ := json.Marshal(InspectionResponse{ID: request.ID, RiskLevel: "LOW", SanitizedBody: request.Body})
				_, _ = connection.Write(append(payload, '\n'))
			}
		}
		_ = connection.Close()
		connection, acceptErr = listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
	}()

	originCalls := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originCalls++
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte("origin response"))
		_ = writer.Close()
	}))
	defer origin.Close()
	core := &proxyCore{
		engine:             newUDSClientWithTimeout(socketPath, FailClosed, time.Second, log.New(io.Discard, "", 0)),
		modes:              newActiveMode(modeMonitor),
		events:             newEventHub(),
		inspectRequests:    true,
		inspectResponses:   true,
		inspectHeadersFlag: true,
		maxBodyBytes:       1024,
	}
	client := newPlainHTTPProxyClient(t, core)
	request, err := http.NewRequest(http.MethodGet, origin.URL+"/response", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept-Encoding", "gzip")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || response.Status != "503 Service Unavailable" ||
		response.Header.Get("Content-Type") != "text/plain; charset=utf-8" ||
		string(body) != "response blocked: inspection engine unavailable\n" {
		t.Fatalf("FAIL_CLOSED response = %d %q, want 503 inspection-unavailable", response.StatusCode, body)
	}
	if originCalls != 1 {
		t.Fatalf("origin calls = %d, want one successful request before response inspection failed", originCalls)
	}
	responseEventFound := false
	for _, event := range core.events.snapshot(string(modeMonitor)).Events {
		if event.ConnectionType == "response" {
			responseEventFound = true
			if event.Status != "blocked" || event.Inspected {
				t.Fatalf("response event = %#v, want blocked and inspected=false", event)
			}
		}
	}
	if !responseEventFound {
		t.Fatal("missing blocked response inspection event")
	}
}

func TestPlainHTTPProxyFailClosedRequestDoesNotReachOrigin(t *testing.T) {
	originCalls := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originCalls++
		_, _ = w.Write([]byte("must not be reached"))
	}))
	defer origin.Close()
	core := &proxyCore{
		engine:          newUDSClientWithTimeout(shortTestSocketPath(t), FailClosed, time.Second, log.New(io.Discard, "", 0)),
		modes:           newActiveMode(modeMonitor),
		events:          newEventHub(),
		securityPolicy:  AllowUninspected,
		inspectRequests: true,
	}
	client := newPlainHTTPProxyClient(t, core)
	response, err := client.Get(origin.URL + "/request")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || string(body) != "request blocked: inspection engine unavailable\n" {
		t.Fatalf("FAIL_CLOSED request = %d %q, want 503 inspection-unavailable", response.StatusCode, body)
	}
	if originCalls != 0 {
		t.Fatalf("origin calls = %d, want zero after FAIL_CLOSED inspection failure", originCalls)
	}
	events := core.events.snapshot(string(modeMonitor)).Events
	if len(events) != 1 || events[0].Status != "blocked" || events[0].Inspected {
		t.Fatalf("request event = %#v, want blocked and inspected=false", events)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestPlainHTTPProxyResponseInspectionModes(t *testing.T) {
	for _, mode := range []inspectionMode{modeMonitor, modeSanitize, modeBlock} {
		for _, scenario := range []struct {
			name       string
			body       string
			compressed bool
			limit      int64
		}{
			{name: "clean", body: "clean response", limit: 1024},
			{name: "secret", body: "SECRET response", limit: 1024},
			{name: "compressed secret", body: "SECRET compressed response", compressed: true, limit: 1024},
			{name: "over limit", body: "response exceeds limit", limit: 8},
		} {
			t.Run(string(mode)+"/"+scenario.name, func(t *testing.T) {
				body := []byte(scenario.body)
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if scenario.compressed {
						w.Header().Set("Content-Encoding", "gzip")
						writer := gzip.NewWriter(w)
						_, _ = writer.Write(body)
						_ = writer.Close()
						return
					}
					_, _ = w.Write(body)
				}))
				defer origin.Close()

				core := newHTTPProxyTestCore(t, mode, scenario.limit)
				client := newPlainHTTPProxyClient(t, core)
				request, err := http.NewRequest(http.MethodGet, origin.URL+"/response", nil)
				if err != nil {
					t.Fatal(err)
				}
				if scenario.compressed {
					request.Header.Set("Accept-Encoding", "gzip")
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				wireBody, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}

				wantStatus, wantBody, wantEvent, wantInspected := http.StatusOK, scenario.body, "passed", true
				switch scenario.name {
				case "secret", "compressed secret":
					switch mode {
					case modeSanitize:
						wantBody, wantEvent = strings.ReplaceAll(scenario.body, "SECRET", "[REDACTED]"), "sanitized"
					case modeBlock:
						wantStatus, wantBody, wantEvent = http.StatusForbidden, "response blocked by DLP policy\n", "blocked"
					}
				case "over limit":
					wantEvent, wantInspected = "body_too_large", false
					if mode != modeMonitor {
						wantStatus, wantBody, wantEvent = http.StatusForbidden, "response blocked: body was not fully inspected\n", "blocked"
					}
				}

				gotBody := string(wireBody)
				if scenario.compressed && wantStatus == http.StatusOK {
					reader, err := gzip.NewReader(strings.NewReader(gotBody))
					if err != nil {
						t.Fatalf("read gzip response: %v", err)
					}
					decompressed, err := io.ReadAll(reader)
					_ = reader.Close()
					if err != nil {
						t.Fatal(err)
					}
					gotBody = string(decompressed)
				}
				if response.StatusCode != wantStatus || gotBody != wantBody {
					t.Fatalf("response = %d %q, want %d %q", response.StatusCode, gotBody, wantStatus, wantBody)
				}
				if scenario.compressed && mode == modeSanitize && wantEvent == "sanitized" && response.Header.Get("Content-Encoding") != "gzip" {
					t.Fatalf("sanitized response Content-Encoding = %q, want gzip", response.Header.Get("Content-Encoding"))
				}

				events := core.events.snapshot(string(mode)).Events
				if len(events) != 2 {
					t.Fatalf("request/response inspection event count = %d, want 2", len(events))
				}
				var event inspectionEvent
				for _, candidate := range events {
					if candidate.ConnectionType == "response" {
						event = candidate
						break
					}
				}
				if event.ConnectionType != "response" || event.Protocol != "HTTP" || event.Status != wantEvent || event.Inspected != wantInspected {
					t.Fatalf("response inspection event = %#v; want status=%s inspected=%v HTTP", event, wantEvent, wantInspected)
				}
			})
		}
	}
}

func TestMergeSanitizedHeadersValidatesEngineOutput(t *testing.T) {
	original := map[string]string{
		"X-API-Key":      testAnthropicKey,
		"Content-Length": "10",
		"Connection":     "X-Hop",
		"X-Hop":          "original",
		"X-Safe":         "original",
	}
	engine := map[string]string{
		"X-API-Key":      "[REDACTED_ANTHROPIC_KEY]",
		"Content-Length": "1",
		"X-Hop":          "changed",
		"X-Safe":         "invalid\r\nInjected: yes",
		"X-New":          "added",
	}
	got := mergeSanitizedHeaders(original, engine, map[string]string{"X-Safe": "original"})
	if got["X-API-Key"] != "[REDACTED_ANTHROPIC_KEY]" || got["Content-Length"] != "10" || got["X-Hop"] != "original" || got["X-Safe"] != "original" {
		t.Fatalf("merged sanitized headers = %#v", got)
	}
	if _, exists := got["X-New"]; exists {
		t.Fatalf("engine added a header not present in the original: %#v", got)
	}
	if original["X-API-Key"] != testAnthropicKey || engine["Content-Length"] != "1" {
		t.Fatalf("merge mutated source maps: original=%#v engine=%#v", original, engine)
	}
}
