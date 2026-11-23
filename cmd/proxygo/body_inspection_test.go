package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var errBodyReadTest = errors.New("test body read failure")

type failingBody struct {
	failed bool
	tail   *strings.Reader
}

func (b *failingBody) Read(data []byte) (int, error) {
	if !b.failed {
		b.failed = true
		return copy(data, "prefix"), errBodyReadTest
	}
	return b.tail.Read(data)
}

func (b *failingBody) Close() error { return nil }

func newBodyInspectionTestCore(t *testing.T, mode inspectionMode, maxBytes int64) *proxyCore {
	t.Helper()
	return &proxyCore{
		engine:             newUDSClientWithTimeout(startFakeEngine(t), FailClosed, time.Second, log.New(io.Discard, "", 0)),
		modes:              newActiveMode(mode),
		events:             newEventHub(),
		securityPolicy:     BlockUninspected,
		inspectRequests:    true,
		inspectResponses:   true,
		inspectHeadersFlag: true,
		maxBodyBytes:       maxBytes,
	}
}

func lastInspectionEvent(t *testing.T, core *proxyCore) inspectionEvent {
	t.Helper()
	events := core.events.snapshot(string(core.modes.current())).Events
	if len(events) == 0 {
		t.Fatal("inspection event was not published")
	}
	return events[len(events)-1]
}

func TestInspectRequestBodyBoundariesPreserveOriginal(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus string
		inspected  bool
	}{
		{name: "below limit", body: "1234567", wantStatus: "passed", inspected: true},
		{name: "at limit", body: "12345678", wantStatus: "passed", inspected: true},
		{name: "over limit with secret after limit", body: "12345678 sk-ant-api03-abcdefghijklmnopqrstuvwx", wantStatus: "body_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := newBodyInspectionTestCore(t, modeMonitor, 8)
			request := httptest.NewRequest(http.MethodPost, "http://example.test/path", nil)
			request.Body = io.NopCloser(strings.NewReader(test.body))
			request.ContentLength = int64(len(test.body))
			request.Header.Set("Content-Length", strconv.Itoa(len(test.body)))
			recorder := httptest.NewRecorder()

			if !core.inspectRequest(recorder, request, "example.test") {
				t.Fatal("MONITOR unexpectedly blocked the request")
			}
			gotBody, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("read forwarded body: %v", err)
			}
			if string(gotBody) != test.body {
				t.Fatalf("forwarded body = %q, want original %q", gotBody, test.body)
			}
			if request.ContentLength != int64(len(test.body)) || request.Header.Get("Content-Length") != strconv.Itoa(len(test.body)) {
				t.Fatalf("request framing changed: ContentLength=%d header=%q", request.ContentLength, request.Header.Get("Content-Length"))
			}
			event := lastInspectionEvent(t, core)
			if event.Status != test.wantStatus || event.Inspected != test.inspected {
				t.Fatalf("event status/inspected = %q/%v, want %q/%v", event.Status, event.Inspected, test.wantStatus, test.inspected)
			}
			if strings.Contains(test.body, "sk-ant-") && len(event.Findings) != 0 {
				t.Fatalf("oversized body was partially inspected: findings=%v", event.Findings)
			}
		})
	}
}

func TestInspectResponseBodyBoundariesPreserveOriginal(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus string
		inspected  bool
	}{
		{name: "below limit", body: "1234567", wantStatus: "passed", inspected: true},
		{name: "at limit", body: "12345678", wantStatus: "passed", inspected: true},
		{name: "over limit with secret after limit", body: "12345678 sk-ant-api03-abcdefghijklmnopqrstuvwx", wantStatus: "body_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := newBodyInspectionTestCore(t, modeMonitor, 8)
			response := &http.Response{
				StatusCode:    http.StatusOK,
				Header:        make(http.Header),
				Body:          io.NopCloser(strings.NewReader(test.body)),
				ContentLength: int64(len(test.body)),
				Request:       httptest.NewRequest(http.MethodGet, "https://example.test/path", nil),
			}
			response.Header.Set("Content-Length", strconv.Itoa(len(test.body)))

			if err := core.inspectResponse(response, "example.test"); err != nil {
				t.Fatalf("inspect response: %v", err)
			}
			gotBody, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read forwarded body: %v", err)
			}
			if string(gotBody) != test.body {
				t.Fatalf("forwarded body = %q, want original %q", gotBody, test.body)
			}
			if response.ContentLength != int64(len(test.body)) || response.Header.Get("Content-Length") != strconv.Itoa(len(test.body)) {
				t.Fatalf("response framing changed: ContentLength=%d header=%q", response.ContentLength, response.Header.Get("Content-Length"))
			}
			event := lastInspectionEvent(t, core)
			if event.Status != test.wantStatus || event.Inspected != test.inspected {
				t.Fatalf("event status/inspected = %q/%v, want %q/%v", event.Status, event.Inspected, test.wantStatus, test.inspected)
			}
			if strings.Contains(test.body, "sk-ant-") && len(event.Findings) != 0 {
				t.Fatalf("oversized body was partially inspected: findings=%v", event.Findings)
			}
		})
	}
}

func TestInspectRequestChunkedOversizedBodyPreservesTransferEncoding(t *testing.T) {
	core := newBodyInspectionTestCore(t, modeMonitor, 4)
	request := httptest.NewRequest(http.MethodPost, "http://example.test/path", nil)
	request.Body = io.NopCloser(strings.NewReader("123456"))
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Transfer-Encoding", "chunked")

	if !core.inspectRequest(httptest.NewRecorder(), request, "example.test") {
		t.Fatal("MONITOR unexpectedly blocked the request")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "123456" {
		t.Fatalf("forwarded body = %q, err=%v", body, err)
	}
	if request.ContentLength != -1 || len(request.TransferEncoding) != 1 || request.TransferEncoding[0] != "chunked" || request.Header.Get("Transfer-Encoding") != "chunked" {
		t.Fatalf("request transfer framing changed: length=%d encoding=%v header=%q", request.ContentLength, request.TransferEncoding, request.Header.Get("Transfer-Encoding"))
	}
}

func TestInspectResponseChunkedOversizedBodyPreservesTransferEncoding(t *testing.T) {
	core := newBodyInspectionTestCore(t, modeMonitor, 4)
	response := &http.Response{
		StatusCode:       http.StatusOK,
		Header:           make(http.Header),
		Body:             io.NopCloser(strings.NewReader("123456")),
		ContentLength:    -1,
		TransferEncoding: []string{"chunked"},
		Request:          httptest.NewRequest(http.MethodGet, "https://example.test/path", nil),
	}
	response.Header.Set("Transfer-Encoding", "chunked")

	if err := core.inspectResponse(response, "example.test"); err != nil {
		t.Fatalf("inspect response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "123456" {
		t.Fatalf("forwarded body = %q, err=%v", body, err)
	}
	if response.ContentLength != -1 || len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked" || response.Header.Get("Transfer-Encoding") != "chunked" {
		t.Fatalf("response transfer framing changed: length=%d encoding=%v header=%q", response.ContentLength, response.TransferEncoding, response.Header.Get("Transfer-Encoding"))
	}
}

func TestInspectRequestReadErrorIsRecordedAndReplayable(t *testing.T) {
	core := newBodyInspectionTestCore(t, modeMonitor, 8)
	request := httptest.NewRequest(http.MethodPost, "http://example.test/path", nil)
	request.Body = &failingBody{tail: strings.NewReader("tail")}
	recorder := httptest.NewRecorder()

	if !core.inspectRequest(recorder, request, "example.test") {
		t.Fatal("MONITOR unexpectedly blocked the request")
	}
	first, err := io.ReadAll(request.Body)
	if !errors.Is(err, errBodyReadTest) || string(first) != "prefix" {
		t.Fatalf("first replay read = %q, err=%v", first, err)
	}
	second, err := io.ReadAll(request.Body)
	if err != nil || string(second) != "tail" {
		t.Fatalf("remainder after read error = %q, err=%v", second, err)
	}
	event := lastInspectionEvent(t, core)
	if event.Status != "body_read_error" || event.Inspected {
		t.Fatalf("read error event = %q inspected=%v", event.Status, event.Inspected)
	}
}

func TestInspectResponseReadErrorIsRecordedAndReplayable(t *testing.T) {
	core := newBodyInspectionTestCore(t, modeMonitor, 8)
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       &failingBody{tail: strings.NewReader("tail")},
		Request:    httptest.NewRequest(http.MethodGet, "https://example.test/path", nil),
	}

	if err := core.inspectResponse(response, "example.test"); err != nil {
		t.Fatalf("MONITOR returned error: %v", err)
	}
	first, err := io.ReadAll(response.Body)
	if !errors.Is(err, errBodyReadTest) || string(first) != "prefix" {
		t.Fatalf("first replay read = %q, err=%v", first, err)
	}
	second, err := io.ReadAll(response.Body)
	if err != nil || string(second) != "tail" {
		t.Fatalf("remainder after read error = %q, err=%v", second, err)
	}
	event := lastInspectionEvent(t, core)
	if event.Status != "body_read_error" || event.Inspected {
		t.Fatalf("read error event = %q inspected=%v", event.Status, event.Inspected)
	}
}

func TestIncompleteBodiesAreBlockedOutsideMonitor(t *testing.T) {
	for _, mode := range []inspectionMode{modeBlock, modeSanitize} {
		t.Run(string(mode), func(t *testing.T) {
			t.Run("request", func(t *testing.T) {
				core := newBodyInspectionTestCore(t, mode, 4)
				request := httptest.NewRequest(http.MethodPost, "http://example.test/path", strings.NewReader("123456"))
				if core.inspectRequest(httptest.NewRecorder(), request, "example.test") {
					t.Fatal("incomplete request body was allowed")
				}
				if event := lastInspectionEvent(t, core); event.Status != "blocked" || event.Inspected {
					t.Fatalf("request event = %q inspected=%v", event.Status, event.Inspected)
				}
			})
			t.Run("response", func(t *testing.T) {
				core := newBodyInspectionTestCore(t, mode, 4)
				response := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("123456")),
					Request:    httptest.NewRequest(http.MethodGet, "https://example.test/path", nil),
				}
				if err := core.inspectResponse(response, "example.test"); err != nil {
					t.Fatalf("inspect response: %v", err)
				}
				if response.StatusCode != http.StatusForbidden {
					t.Fatalf("response status = %d, want 403", response.StatusCode)
				}
				if event := lastInspectionEvent(t, core); event.Status != "blocked" || event.Inspected {
					t.Fatalf("response event = %q inspected=%v", event.Status, event.Inspected)
				}
			})
		})
	}
}

func TestReadBoundedBodyReportsAndReplaysReadError(t *testing.T) {
	source := &failingBody{tail: strings.NewReader("tail")}
	result := readBoundedBody(source, 8)
	if result.readError == nil || result.tooLarge {
		t.Fatalf("read result error=%v tooLarge=%v", result.readError, result.tooLarge)
	}
	first, err := io.ReadAll(result.replay)
	if !errors.Is(err, errBodyReadTest) || string(first) != "prefix" {
		t.Fatalf("first replay read = %q, err=%v", first, err)
	}
	second, err := io.ReadAll(result.replay)
	if err != nil || string(second) != "tail" {
		t.Fatalf("remainder after read error = %q, err=%v", second, err)
	}
}
