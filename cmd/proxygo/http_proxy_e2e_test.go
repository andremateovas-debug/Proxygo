package main

import (
	"compress/gzip"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testAnthropicKey = "sk-ant-api03-abcdefghijklmnopqrstuvwx"

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
