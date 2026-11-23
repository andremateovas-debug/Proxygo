package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestTUIOverlayNavigationAndDetails(t *testing.T) {
	model := tuiModel{
		width:  80,
		height: 24,
		filter: "ALL",
		events: []tuiEvent{{
			Seq:           1,
			Timestamp:     time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
			Host:          "api.example.test",
			Method:        "POST",
			Category:      "SECRET",
			RiskLevel:     "HIGH",
			Status:        "sanitized",
			SanitizedBody: `{"token":"[REDACTED_SECRET]"}`,
			Findings:      []tuiFinding{{Kind: "SECRET", Path: "body.token"}},
		}},
	}
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
	model = updated.(tuiModel)
	if model.overlay != "menu" {
		t.Fatalf("Tab overlay = %q, want menu", model.overlay)
	}
	model.menuIndex = 5
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(tuiModel)
	if model.filter != "HIGH" || model.overlay != "" {
		t.Fatalf("menu filter = %q, overlay = %q", model.filter, model.overlay)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(tuiModel)
	if model.overlay != "detail" {
		t.Fatalf("Enter overlay = %q, want detail", model.overlay)
	}
	view := model.View()
	if !strings.Contains(view, "[REDACTED_SECRET]") || !strings.Contains(view, "body.token") {
		t.Fatalf("event detail omitted sanitized body or findings: %s", view)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEscape})
	model = updated.(tuiModel)
	if model.overlay != "" {
		t.Fatalf("Escape left overlay %q open", model.overlay)
	}
	_, quit := model.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if quit == nil {
		t.Fatal("Escape on the main view did not request quit")
	}
	if _, ok := quit().(tea.QuitMsg); !ok {
		t.Fatal("main-view Escape did not return tea.QuitMsg")
	}
}

func TestResolveTUIEndpointsUsesConfiguredAddresses(t *testing.T) {
	values := map[string]string{
		"PROXYGO_PROXY_ADDR": "http://127.0.0.1:8088/",
		"PROXY_ADDR":         "127.0.0.1:8090",
		"PROXYGO_DASH_ADDR":  "127.0.0.1:8089",
	}
	endpoints, err := resolveTUIEndpoints(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if endpoints.proxyURL != "http://127.0.0.1:8088" {
		t.Fatalf("proxy URL = %q, want configured PROXYGO_PROXY_ADDR", endpoints.proxyURL)
	}
	if endpoints.dashboardURL != "http://127.0.0.1:8089" {
		t.Fatalf("dashboard URL = %q, want configured PROXYGO_DASH_ADDR", endpoints.dashboardURL)
	}

	transport, err := newReactionTransport(endpoints.proxyURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodPost, "http://httpbin.org/post", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := transport.Proxy(request)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL.Host != "127.0.0.1:8088" {
		t.Fatalf("reaction transport proxy = %q, want 127.0.0.1:8088", proxyURL.Host)
	}
}

func TestResolveTUIEndpointsAliasAndFallback(t *testing.T) {
	t.Run("PROXY_ADDR alias with no scheme", func(t *testing.T) {
		values := map[string]string{"PROXY_ADDR": "127.0.0.1:8092"}
		endpoints, err := resolveTUIEndpoints(func(key string) string { return values[key] })
		if err != nil {
			t.Fatal(err)
		}
		if endpoints.proxyURL != "http://127.0.0.1:8092" {
			t.Fatalf("proxy URL = %q, want normalized alias", endpoints.proxyURL)
		}
	})

	t.Run("default addresses", func(t *testing.T) {
		endpoints, err := resolveTUIEndpoints(func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		if endpoints.proxyURL != "http://127.0.0.1:8080" {
			t.Fatalf("proxy fallback = %q, want http://127.0.0.1:8080", endpoints.proxyURL)
		}
		if endpoints.dashboardURL != "http://127.0.0.1:8081" {
			t.Fatalf("dashboard fallback = %q, want http://127.0.0.1:8081", endpoints.dashboardURL)
		}
	})

	t.Run("invalid address does not silently fallback", func(t *testing.T) {
		_, err := resolveTUIEndpoints(func(key string) string {
			if key == "PROXYGO_PROXY_ADDR" {
				return "file:///tmp/proxy"
			}
			return ""
		})
		if err == nil {
			t.Fatal("unsupported proxy scheme was silently accepted")
		}
	})
}

func TestLoadTUIAdminTokenFromEnvironmentOrFile(t *testing.T) {
	t.Run("environment", func(t *testing.T) {
		values := map[string]string{"PROXYGO_ADMIN_TOKEN": strings.Repeat("env-token-", 4)}
		token, err := loadTUIAdminToken(func(key string) string { return values[key] })
		if err != nil || token != values["PROXYGO_ADMIN_TOKEN"] {
			t.Fatalf("token = %q, err=%v", token, err)
		}
	})

	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "admin.token")
		want := strings.Repeat("file-token-", 4)
		if err := os.WriteFile(path, []byte(want+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		values := map[string]string{"PROXYGO_ADMIN_TOKEN_FILE": path}
		token, err := loadTUIAdminToken(func(key string) string { return values[key] })
		if err != nil || token != want {
			t.Fatalf("token = %q, err=%v", token, err)
		}
	})
}

func TestTUIAdminHeadersIncludeBearerAndOrigin(t *testing.T) {
	model := tuiModel{adminToken: strings.Repeat("tui-token-", 4), dashboardURL: "http://127.0.0.1:8081"}
	for _, target := range []string{"/api/state", "/events", "/api/mode"} {
		t.Run(target, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, model.dashboardURL+target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.setAdminHeaders(request); err != nil {
				t.Fatal(err)
			}
			if request.Header.Get("Authorization") != "Bearer "+model.adminToken {
				t.Fatal("TUI request omitted its bearer token")
			}
			if request.Header.Get("Origin") != model.dashboardURL {
				t.Fatalf("Origin = %q, want %q", request.Header.Get("Origin"), model.dashboardURL)
			}
		})
	}
}

func TestConfiguredReactionCAPoolUsesConfiguredDirectory(t *testing.T) {
	caDir := t.TempDir()
	t.Setenv("PROXYGO_CA_DIR", caDir)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"ProxyGo TUI Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(caDir, "ca.crt"), certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	pool, err := configuredReactionCAPool()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, subject := range pool.Subjects() {
		if strings.Contains(string(subject), "ProxyGo TUI Test") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("configured ca.crt was not added to the HTTPS test trust pool")
	}
}

func TestTUIHotkeysAndSSEDeduplication(t *testing.T) {
	model := tuiModel{filter: "ALL", stream: make(chan tuiStreamResult, 4), ctx: context.Background()}
	for _, test := range []struct {
		key  string
		mode string
	}{{"1", "MONITOR"}, {"2", "SANITIZE"}, {"3", "BLOCK"}} {
		updated, command := model.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(test.key)})
		model = updated.(tuiModel)
		if command == nil || !model.busy || !strings.Contains(model.status, test.mode) {
			t.Fatalf("mode hotkey %s did not provide immediate feedback", test.key)
		}
		model.busy = false
	}
	model.overlay = "tests"
	updated, command := model.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("5")})
	model = updated.(tuiModel)
	if command == nil || !strings.Contains(model.testStatus, "Prueba 5 en curso") {
		t.Fatal("reaction test hotkey did not start asynchronously")
	}

	event := &tuiEvent{Seq: 7, Timestamp: time.Now(), Host: "example.test", Status: "blocked", RiskLevel: "HIGH"}
	model.overlay = ""
	updated, _ = model.Update(tuiStreamResult{event: event})
	model = updated.(tuiModel)
	updated, _ = model.Update(tuiStreamResult{event: event})
	model = updated.(tuiModel)
	if len(model.events) != 1 || model.alertCount != 1 || model.lastSeq != 7 {
		t.Fatalf("duplicate SSE event was not ignored: events=%d alerts=%d seq=%d", len(model.events), model.alertCount, model.lastSeq)
	}
}

func TestTUIViewFitsCompactTerminal(t *testing.T) {
	model := tuiModel{
		width:  32,
		height: 6,
		mode:   "BLOCK",
		filter: "ALL",
		events: []tuiEvent{{Timestamp: time.Now(), Host: "a-very-long-hostname.example.test", Status: "blocked", RiskLevel: "HIGH"}},
	}
	view := model.View()
	for _, line := range strings.Split(view, "\n") {
		if width := lipgloss.Width(line); width > model.width {
			t.Errorf("compact row width = %d, want <= %d: %s", width, model.width, line)
		}
	}
	model.overlay = "detail"
	model.events[0].SanitizedBody = strings.Repeat("long sanitized value ", 200)
	view = model.View()
	if height := lipgloss.Height(view); height > model.height {
		t.Errorf("compact detail height = %d, want <= %d", height, model.height)
	}
}

func TestTUIStateMergesSnapshotAndLiveEvents(t *testing.T) {
	model := tuiModel{events: []tuiEvent{{Seq: 12, Host: "live.test"}}}
	updated, _ := model.Update(tuiStateMsg{state: tuiState{
		Seq:        11,
		Events:     []tuiEvent{{Seq: 11, Host: "snapshot.test"}, {Seq: 12, Host: "live.test"}},
		Buckets:    []tuiBucket{{Minute: 123000, Clean: 4, Alerts: 2}},
		tuiCAState: tuiCAState{CAEnabled: true, CACertPath: "/tmp/ca.crt"},
	}})
	model = updated.(tuiModel)
	if len(model.events) != 2 || model.events[0].Seq != 12 || model.events[1].Seq != 11 {
		t.Fatalf("merged events = %+v", model.events)
	}
	if !model.ca.CAEnabled || model.ca.CACertPath != "/tmp/ca.crt" || len(model.buckets) != 1 {
		t.Fatalf("snapshot CA/buckets not applied: %+v %+v", model.ca, model.buckets)
	}
}
