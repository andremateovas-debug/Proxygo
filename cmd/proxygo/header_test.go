package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestExtractCredential(t *testing.T) {
	tests := []struct {
		header string
		value  string
		want   string
	}{
		{"authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature"},
		{"authorization", "Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		{"authorization", "Token abc123", "Token abc123"},
		{"proxy-authorization", "Bearer token123", "token123"},
		{"x-api-key", "sk-ant-api03-abcdefghijklmnopqrstuvwx", "sk-ant-api03-abcdefghijklmnopqrstuvwx"},
		{"x-custom-key", "my-secret-value", "my-secret-value"},
		{"cookie", "session=abc123", ""},
		{"content-type", "application/json", ""},
		{"", "", ""},
	}
	for _, test := range tests {
		got := extractCredential(test.header, test.value)
		if got != test.want {
			t.Errorf("extractCredential(%q, %q) = %q, want %q", test.header, test.value, got, test.want)
		}
	}
}

func TestHeaderMap(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer token123")
	h.Set("X-API-Key", "key456")
	h.Add("Cookie", "a=1")
	h.Add("Cookie", "b=2")

	m := headerMap(h)
	if m["Authorization"] != "Bearer token123" {
		t.Errorf("headerMap Authorization = %q, want Bearer token123", m["Authorization"])
	}
	// http.Header canonicalizes keys: X-API-Key -> X-Api-Key
	foundAPIKey := false
	for k, v := range m {
		if strings.EqualFold(k, "X-API-Key") && v == "key456" {
			foundAPIKey = true
		}
	}
	if !foundAPIKey {
		t.Errorf("headerMap should contain X-API-Key=key456, got %v", m)
	}
	if m["Cookie"] != "a=1" {
		t.Errorf("headerMap Cookie = %q, want a=1 (first value)", m["Cookie"])
	}
}

func TestIsCompressed(t *testing.T) {
	tests := []struct {
		encoding string
		want     bool
	}{
		{"gzip", true},
		{"deflate", true},
		{"br", true},
		{"identity", false},
		{"", false},
	}
	for _, test := range tests {
		resp := &http.Response{Header: http.Header{}}
		if test.encoding != "" {
			resp.Header.Set("Content-Encoding", test.encoding)
		}
		got := isCompressed(resp)
		if got != test.want {
			t.Errorf("isCompressed(%q) = %v, want %v", test.encoding, got, test.want)
		}
	}
}

func TestSimpleHash(t *testing.T) {
	if simpleHash("") != 0 {
		t.Error("simpleHash empty should be 0")
	}
	if simpleHash("a") != simpleHash("a") {
		t.Error("simpleHash should be deterministic")
	}
	if simpleHash("a") == simpleHash("b") {
		t.Error("simpleHash should differ for different inputs")
	}
}

func TestInspectHeadersFromMapNoLeak(t *testing.T) {
	core := &proxyCore{}
	headers := map[string]string{
		"authorization": "Bearer token-A",
		"x-api-key":     "key-A",
	}
	findings, sanitized := core.inspectHeadersFromMap(headers, "api.example.com", modeMonitor)

	if len(findings) != 0 {
		t.Errorf("expected no findings on first sight, got %d", len(findings))
	}
	if sanitized["authorization"] != "Bearer token-A" {
		t.Errorf("sanitized authorization should be unchanged on first sight")
	}
	if sanitized["x-api-key"] != "key-A" {
		t.Errorf("sanitized x-api-key should be unchanged on first sight")
	}
}

func TestInspectHeadersFromMapCredentialLeak(t *testing.T) {
	core := &proxyCore{}

	// First sight: token-A on api.example.com
	headers1 := map[string]string{"authorization": "Bearer token-A"}
	_, _ = core.inspectHeadersFromMap(headers1, "api.example.com", modeMonitor)

	// Second sight: same token on different host -> leak
	headers2 := map[string]string{"authorization": "Bearer token-A"}
	findings, sanitized := core.inspectHeadersFromMap(headers2, "evil.example.com", modeMonitor)

	if len(findings) != 1 {
		t.Errorf("expected 1 finding for credential leak, got %d", len(findings))
	}
	if findings[0].Kind != "CREDENTIAL_LEAK" {
		t.Errorf("expected CREDENTIAL_LEAK, got %s", findings[0].Kind)
	}
	if !strings.Contains(findings[0].Path, "header.authorization") {
		t.Errorf("expected path to contain header.authorization, got %s", findings[0].Path)
	}
	if sanitized["authorization"] != "Bearer token-A" {
		t.Errorf("monitor mode should not sanitize, got %q", sanitized["authorization"])
	}
}

func TestInspectHeadersFromMapSanitizeLeak(t *testing.T) {
	core := &proxyCore{}

	headers1 := map[string]string{"x-api-key": "secret-key-123"}
	_, _ = core.inspectHeadersFromMap(headers1, "api.example.com", modeMonitor)

	headers2 := map[string]string{"x-api-key": "secret-key-123"}
	_, sanitized := core.inspectHeadersFromMap(headers2, "evil.example.com", modeSanitize)

	if sanitized["x-api-key"] != "" {
		t.Errorf("sanitize mode should clear leaked credential, got %q", sanitized["x-api-key"])
	}
}

func TestSanitizeHeaderPreview(t *testing.T) {
	short := "short value"
	long := strings.Repeat("a", 200)

	m := map[string]string{
		"short": short,
		"long":  long,
	}
	preview := sanitizeHeaderPreview(m)

	if preview["short"] != short {
		t.Errorf("short header should not be truncated")
	}
	if len(preview["long"]) != 128+3 {
		t.Errorf("long header should be truncated to 128 chars + ...")
	}
	if !strings.HasSuffix(preview["long"], "...") {
		t.Errorf("truncated header should end with ...")
	}
}

func TestEventID(t *testing.T) {
	id1 := eventID()
	id2 := eventID()
	if id1 == id2 {
		t.Error("event IDs should be unique")
	}
	if !strings.HasPrefix(id1, "evt-") {
		t.Errorf("event ID should start with evt-, got %s", id1)
	}
}

func TestClientID(t *testing.T) {
	r := &http.Request{
		Header:     http.Header{"Authorization": {"Bearer secret-token"}},
		RemoteAddr: "10.0.0.1:12345",
	}
	id := clientID(r)
	if id == "" {
		t.Error("clientID should not be empty")
	}
	if !strings.HasPrefix(id, "auth-") {
		t.Errorf("clientID with auth should start with auth-, got %s", id)
	}

	r2 := &http.Request{RemoteAddr: "10.0.0.2:54321"}
	id2 := clientID(r2)
	if !strings.HasPrefix(id2, "ip-") {
		t.Errorf("clientID without auth should start with ip-, got %s", id2)
	}
}