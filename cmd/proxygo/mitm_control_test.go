package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCAControlAPIAndPreservesFilesWhenDisabled(t *testing.T) {
	caDir := filepath.Join(t.TempDir(), "ca")
	t.Setenv("PROXYGO_CA_DIR", caDir)
	t.Setenv("PROXYGO_CA_ORG", "Control Test")
	t.Setenv("PROXYGO_CONNECT_PORTS", "443")
	t.Setenv("PROXYGO_CONNECT_ALLOWED_HOSTS", "")

	events := newEventHub()
	stateEvents, ok := events.subscribe()
	if !ok {
		t.Fatal("could not subscribe to state events")
	}
	defer events.unsubscribe(stateEvents)
	modes := newActiveMode(modeMonitor)
	core := &proxyCore{modes: modes, events: events}
	controller := newMITMController(core, nil, log.New(io.Discard, "", 0), events)
	adminToken := strings.Repeat("admin-token-", 4)
	adminAuth, err := newAdminAuthenticator(adminToken, true)
	if err != nil {
		t.Fatal(err)
	}
	server := newInternalServer(events, modes, "127.0.0.1:8081", adminAuth, controller)

	request := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/state = %d, want 200", response.Code)
	}
	var initial caPublicState
	if err := json.Unmarshal(response.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if initial.CAEnabled || initial.CACertPath != filepath.Join(caDir, "ca.crt") {
		t.Fatalf("initial CA state = %+v", initial)
	}

	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/ca", strings.NewReader(body))
		request.Header.Set("Origin", "http://"+request.Host)
		request.Header.Set("Authorization", "Bearer "+adminToken)
		server.Handler.ServeHTTP(recorder, request)
		return recorder
	}
	if response := post(`{"enabled":true}`); response.Code != http.StatusInternalServerError {
		t.Fatalf("CA enable without allowlist = %d, want 500", response.Code)
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca.key")); !os.IsNotExist(err) {
		t.Fatalf("CA key exists after rejected activation: %v", err)
	}

	t.Setenv("PROXYGO_CONNECT_ALLOWED_HOSTS", "example.com")
	enabled := post(`{"enabled":true}`)
	if enabled.Code != http.StatusOK {
		t.Fatalf("CA enable = %d: %s", enabled.Code, enabled.Body.String())
	}
	if strings.Contains(enabled.Body.String(), "PRIVATE KEY") || strings.Contains(enabled.Body.String(), "ca.key") {
		t.Fatal("CA response exposed private-key data")
	}
	var activeState caPublicState
	if err := json.Unmarshal(enabled.Body.Bytes(), &activeState); err != nil {
		t.Fatal(err)
	}
	if !activeState.CAEnabled || activeState.CAOrganization != "Control Test" || activeState.CANotAfter.IsZero() {
		t.Fatalf("active CA state = %+v", activeState)
	}
	keyPath := filepath.Join(caDir, "ca.key")
	certPath := filepath.Join(caDir, "ca.crt")
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-stateEvents:
		if !bytes.Contains(event, []byte(`"type":"state"`)) || !bytes.Contains(event, []byte(`"ca_enabled":true`)) {
			t.Fatalf("unexpected SSE state event: %s", event)
		}
	default:
		t.Fatal("CA activation did not publish an SSE state event")
	}

	disabled := post(`{"enabled":false}`)
	if disabled.Code != http.StatusOK || strings.Contains(disabled.Body.String(), `"ca_enabled":true`) {
		t.Fatalf("CA disable response = %d: %s", disabled.Code, disabled.Body.String())
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("CA private key was removed: %v", err)
	}
	certAfter, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("CA certificate was removed: %v", err)
	}
	if !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(certBefore, certAfter) {
		t.Fatal("disabling MITM changed CA files")
	}
	connectRequest := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	connectRequest.Host = "example.com:443"
	connectResponse := httptest.NewRecorder()
	controller.serve(connectResponse, connectRequest)
	if connectResponse.Code != http.StatusNotImplemented {
		t.Fatalf("CONNECT after CA disable = %d, want 501", connectResponse.Code)
	}
}
