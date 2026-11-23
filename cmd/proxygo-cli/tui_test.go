package main

import (
	"context"
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
