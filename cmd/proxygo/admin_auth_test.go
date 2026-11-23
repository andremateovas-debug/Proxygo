package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testAdminToken = "test-administrative-token-with-sufficient-length"

func mustAdminAuthenticator(t *testing.T, token string, explicit bool) *adminAuthenticator {
	t.Helper()
	auth, err := newAdminAuthenticator(token, explicit)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func authorizedAdminRequest(method, target, token string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(`{"mode":"SANITIZE"}`))
	request.Header.Set("Origin", "http://"+request.Host)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request
}

func TestAdminAuthenticatorRejectsMissingWrongAndManipulatedHeaders(t *testing.T) {
	auth := mustAdminAuthenticator(t, testAdminToken, true)
	tests := []struct {
		name       string
		request    func() *http.Request
		wantStatus int
	}{
		{
			name: "missing token",
			request: func() *http.Request {
				return authorizedAdminRequest(http.MethodPost, "http://admin.example.test/api/mode", "")
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "incorrect token",
			request: func() *http.Request {
				return authorizedAdminRequest(http.MethodPost, "http://admin.example.test/api/mode", strings.Repeat("x", len(testAdminToken)))
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "missing origin",
			request: func() *http.Request {
				request := authorizedAdminRequest(http.MethodPost, "http://admin.example.test/api/mode", testAdminToken)
				request.Header.Del("Origin")
				return request
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "untrusted origin",
			request: func() *http.Request {
				request := authorizedAdminRequest(http.MethodPost, "http://admin.example.test/api/mode", testAdminToken)
				request.Header.Set("Origin", "https://attacker.example")
				return request
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "duplicate authorization headers",
			request: func() *http.Request {
				request := authorizedAdminRequest(http.MethodPost, "http://admin.example.test/api/mode", testAdminToken)
				request.Header.Add("Authorization", "Bearer "+testAdminToken)
				return request
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "duplicate origin headers",
			request: func() *http.Request {
				request := authorizedAdminRequest(http.MethodPost, "http://admin.example.test/api/mode", testAdminToken)
				request.Header.Add("Origin", "http://admin.example.test")
				return request
			},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if auth.authorize(recorder, test.request()) {
				t.Fatal("unauthorized request was accepted")
			}
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if strings.Contains(recorder.Body.String(), testAdminToken) {
				t.Fatal("response exposed an administrative token")
			}
		})
	}
}

func TestAdminModeAndCAOperationsRequireAuthorization(t *testing.T) {
	events := newEventHub()
	modes := newActiveMode(modeMonitor)
	auth := mustAdminAuthenticator(t, testAdminToken, true)
	server := newInternalServer(events, modes, "127.0.0.1:8081", auth)

	post := func(path, token string) *httptest.ResponseRecorder {
		t.Helper()
		recorder := httptest.NewRecorder()
		request := authorizedAdminRequest(http.MethodPost, "http://admin.example.test"+path, token)
		server.Handler.ServeHTTP(recorder, request)
		return recorder
	}
	if response := post("/api/mode", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized mode change = %d, want 401", response.Code)
	}
	if modes.current() != modeMonitor {
		t.Fatal("mode changed without authorization")
	}
	if response := post("/api/mode", strings.Repeat("x", len(testAdminToken))); response.Code != http.StatusUnauthorized {
		t.Fatalf("mode change with incorrect token = %d, want 401", response.Code)
	}
	if modes.current() != modeMonitor {
		t.Fatal("mode changed with an incorrect token")
	}
	if response := post("/api/ca", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized CA operation = %d, want 401", response.Code)
	}
	if response := post("/api/mode", testAdminToken); response.Code != http.StatusOK {
		t.Fatalf("authorized mode change = %d: %s", response.Code, response.Body.String())
	}
	if modes.current() != modeSanitize {
		t.Fatalf("mode = %q, want SANITIZE", modes.current())
	}
	if response := post("/api/ca", testAdminToken); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("authorized CA operation without controller = %d, want 503", response.Code)
	}

	invalid := authorizedAdminRequest(http.MethodPost, "http://admin.example.test/api/mode", testAdminToken)
	invalid.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, invalid)
	if response.Code != http.StatusForbidden || modes.current() != modeSanitize {
		t.Fatalf("cross-origin mode change status/mode = %d/%s, want 403/SANITIZE", response.Code, modes.current())
	}

	badBody := httptest.NewRequest(http.MethodPost, "http://admin.example.test/api/mode", strings.NewReader("{"))
	badBody.Header.Set("Origin", "http://admin.example.test")
	badBody.Header.Set("Authorization", "Bearer "+testAdminToken)
	response = httptest.NewRecorder()
	server.Handler.ServeHTTP(response, badBody)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed mode request = %d, want 400", response.Code)
	}
}

func TestAdminTokenIsGeneratedAndStoredPrivately(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "state", "admin.token")
	t.Setenv(adminTokenEnv, "")
	t.Setenv(adminTokenFileEnv, tokenPath)

	auth, err := loadAdminAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
	if !auth.explicit {
		t.Fatal("explicit token file configuration was not recognized")
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 43 {
		t.Fatalf("generated token length = %d, want at least 43", len(token))
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("token file permissions = %04o, want 0600", info.Mode().Perm())
	}
	if strings.Contains(string(auth.tokenHash[:]), token) {
		t.Fatal("authenticator stores the token instead of its hash")
	}
	if _, err := loadAdminAuthenticator(); err != nil {
		t.Fatalf("reload generated token: %v", err)
	}
}

func TestAdminAuthRejectsWeakTokensAndPublicTokenFiles(t *testing.T) {
	if _, err := newAdminAuthenticator("short", true); err == nil {
		t.Fatal("weak administrative token was accepted")
	}
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(path, []byte(testAdminToken+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdminTokenFile(path); err == nil {
		t.Fatal("group-readable token file was accepted")
	}
}

func TestDashboardAddressRequiresExplicitAuthOffLoopback(t *testing.T) {
	t.Setenv("PROXYGO_DASH_ADDR", "")
	defaultAddress := configuredAddr("PROXYGO_DASH_ADDR", "127.0.0.1:8081")
	if defaultAddress != "127.0.0.1:8081" {
		t.Fatalf("dashboard default = %q, want loopback", defaultAddress)
	}
	if err := validateDashboardAddress(defaultAddress, mustAdminAuthenticator(t, testAdminToken, false)); err != nil {
		t.Fatalf("default loopback address rejected: %v", err)
	}
	if err := validateDashboardAddress("0.0.0.0:8081", mustAdminAuthenticator(t, testAdminToken, false)); err == nil {
		t.Fatal("public dashboard bind accepted without explicit authentication config")
	}
	if err := validateDashboardAddress(":8081", mustAdminAuthenticator(t, testAdminToken, true)); err != nil {
		t.Fatalf("public dashboard bind with explicit token rejected: %v", err)
	}
	if err := validateDashboardAddress("[::1]:8081", mustAdminAuthenticator(t, testAdminToken, false)); err != nil {
		t.Fatalf("IPv6 loopback address rejected: %v", err)
	}
}

func TestStateQueryRedactsSensitiveHeaderValues(t *testing.T) {
	events := newEventHub()
	modes := newActiveMode(modeMonitor)
	auth := mustAdminAuthenticator(t, testAdminToken, true)
	events.publish(inspectionEvent{
		Method: http.MethodPost,
		Host:   "example.test",
		Status: "passed",
		SanitizedHeaders: sanitizeHeaderPreview(map[string]string{
			"Authorization": "Bearer do-not-expose-this-token",
			"X-API-Key":     "do-not-expose-this-api-key",
			"Content-Type":  "application/json",
		}),
	})
	server := newInternalServer(events, modes, "127.0.0.1:8081", auth)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/state = %d, want 200", response.Code)
	}
	if strings.Contains(response.Body.String(), "do-not-expose-this") || strings.Contains(response.Body.String(), "PRIVATE KEY") {
		t.Fatal("state query exposed a credential or private key")
	}
	var state dashboardState
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Events[0].SanitizedHeaders["Authorization"] != "[REDACTED]" || state.Events[0].SanitizedHeaders["X-API-Key"] != "[REDACTED]" {
		t.Fatalf("sensitive headers were not redacted: %#v", state.Events[0].SanitizedHeaders)
	}
}
