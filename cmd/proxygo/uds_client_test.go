package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shortTestSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "pg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return filepath.Join(directory, "engine.sock")
}

func TestUDSClientRejectsSerializedRequestAboveRustLimit(t *testing.T) {
	client := newUDSClientWithTimeout(shortTestSocketPath(t), FailClosed, time.Second, log.New(io.Discard, "", 0))
	request := InspectionRequest{
		ID:      "large-request",
		Method:  http.MethodPost,
		Host:    "example.test",
		Headers: map[string]string{"X-Large": strings.Repeat("x", maxEngineRequestLineBytes)},
	}
	if _, err := client.Inspect(context.Background(), request); err == nil || !strings.Contains(err.Error(), "request line exceeds") {
		t.Fatalf("oversized serialized request error = %v, want request-line limit error", err)
	}
}

func TestFailOpenReturnsInspectionBodyLimitError(t *testing.T) {
	client := newUDSClientWithTimeout(shortTestSocketPath(t), FailOpen, time.Second, log.New(io.Discard, "", 0))
	request := InspectionRequest{ID: "large-body", Body: strings.Repeat("x", maxInspectBodyBytes+1)}
	if response, err := client.Inspect(context.Background(), request); response != nil || !errors.Is(err, ErrInspectionLimitExceeded) {
		t.Fatalf("oversized body inspection = (%v, %v), want an inspection limit error", response, err)
	}
}

func TestFailOpenOversizedRequestLineBlocksWhenSecurityPolicyRequiresInspection(t *testing.T) {
	core := &proxyCore{
		engine:          newUDSClientWithTimeout(shortTestSocketPath(t), FailOpen, time.Second, log.New(io.Discard, "", 0)),
		modes:           newActiveMode(modeMonitor),
		events:          newEventHub(),
		securityPolicy:  BlockUninspected,
		inspectRequests: true,
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.Header.Set("X-Large", strings.Repeat("x", maxEngineRequestLineBytes))
	recorder := httptest.NewRecorder()
	if core.inspectRequest(recorder, request, "example.test") {
		t.Fatal("oversized request line passed despite BLOCK_UNINSPECTED")
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("oversized request status = %d, want 503", recorder.Code)
	}
	events := core.events.snapshot(string(modeMonitor)).Events
	if len(events) != 1 || events[0].Status != "blocked" || events[0].Inspected {
		t.Fatalf("oversized request inspection event = %#v, want blocked/inspected=false", events)
	}
}

func TestReadNDJSONLineHandlesFragmentsAndUnterminatedEOF(t *testing.T) {
	want := `{"id":"` + strings.Repeat("x", 64) + `"}`
	line, err := readNDJSONLine(bufio.NewReaderSize(strings.NewReader(want+"\n"), 16), 256)
	if err != nil || string(line) != want {
		t.Fatalf("fragmented line = %q, err=%v", line, err)
	}
	var response InspectionResponse
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatalf("valid fragmented JSON: %v", err)
	}

	truncated, err := readNDJSONLine(bufio.NewReader(strings.NewReader(`{"id":`)), 256)
	if err != nil {
		t.Fatalf("unterminated EOF read error = %v", err)
	}
	if err := json.Unmarshal(truncated, &response); err == nil {
		t.Fatal("truncated JSON response unexpectedly decoded")
	}
}

func TestFailOpenTruncatedUDSResponsePublishesUninspectedEvent(t *testing.T) {
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
		defer connection.Close()
		_, _ = readNDJSONLine(bufio.NewReader(connection), maxEngineRequestLineBytes)
		_, _ = connection.Write([]byte(`{"id":`))
	}()

	var logOutput bytes.Buffer
	core := &proxyCore{
		engine:          newUDSClientWithTimeout(socketPath, FailOpen, time.Second, log.New(&logOutput, "", 0)),
		modes:           newActiveMode(modeMonitor),
		events:          newEventHub(),
		securityPolicy:  AllowUninspected,
		inspectRequests: true,
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	if !core.inspectRequest(httptest.NewRecorder(), request, "example.test") {
		t.Fatal("FAIL_OPEN rejected the request")
	}
	events := core.events.snapshot(string(modeMonitor)).Events
	if len(events) != 1 || events[0].Status != "fail_open" || events[0].Inspected {
		t.Fatalf("truncated response event = %#v, want fail_open/inspected=false", events)
	}
	if !strings.Contains(logOutput.String(), "SYSTEM ALERT") {
		t.Fatalf("truncated response was not logged as an inspection bypass: %q", logOutput.String())
	}
}
