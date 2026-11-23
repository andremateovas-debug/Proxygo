package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"proxygo/web"
)

const (
	maxRequestBodyBytes = 32 << 20
	maxEventBodyBytes   = 64 << 10
	maxHistoryEvents    = 500
	bucketRetentionMins = 60
)

type inspectionMode string

const (
	modeMonitor  inspectionMode = "MONITOR"
	modeSanitize inspectionMode = "SANITIZE"
	modeBlock    inspectionMode = "BLOCK"
)

type inspectionEvent struct {
	Seq           uint64    `json:"seq,omitempty"`
	ID            string    `json:"id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Method        string    `json:"method"`
	Host          string    `json:"host"`
	Mode          string    `json:"mode"`
	Status        string    `json:"status"`
	Category      string    `json:"category,omitempty"`
	RiskLevel     string    `json:"risk_level,omitempty"`
	Findings      []Finding `json:"findings,omitempty"`
	SanitizedBody string    `json:"sanitized_body,omitempty"`
	BodyTruncated bool      `json:"body_truncated,omitempty"`
}

type minuteBucket struct {
	Minute int64  `json:"minute"`
	Clean  uint64 `json:"clean"`
	Alerts uint64 `json:"alerts"`
}

type dashboardState struct {
	Mode       string            `json:"mode"`
	Seq        uint64            `json:"seq"`
	CleanCount uint64            `json:"clean_count"`
	AlertCount uint64            `json:"alert_count"`
	Buckets    []minuteBucket    `json:"buckets"`
	Events     []inspectionEvent `json:"events"`
}

type activeMode struct {
	value atomic.Value
}

func newActiveMode(initial inspectionMode) *activeMode {
	mode := &activeMode{}
	mode.value.Store(string(initial))
	return mode
}

func (m *activeMode) current() inspectionMode {
	return inspectionMode(m.value.Load().(string))
}

func (m *activeMode) set(mode inspectionMode) {
	m.value.Store(string(mode))
}

type eventHub struct {
	mu          sync.RWMutex
	subscribers map[chan []byte]struct{}
	seq         uint64
	cleanCount  uint64
	alertCount  uint64
	buckets     map[int64]*minuteBucket
	history     []inspectionEvent
}

func newEventHub() *eventHub {
	return &eventHub{
		subscribers: make(map[chan []byte]struct{}),
		buckets:     make(map[int64]*minuteBucket),
		history:     make([]inspectionEvent, 0, maxHistoryEvents),
	}
}

func (h *eventHub) subscribe() (chan []byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subscribers) >= 128 {
		return nil, false
	}
	ch := make(chan []byte, 32)
	h.subscribers[ch] = struct{}{}
	return ch, true
}

func (h *eventHub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.subscribers[ch]; exists {
		delete(h.subscribers, ch)
		close(ch)
	}
}

func isAlertEvent(event inspectionEvent) bool {
	switch strings.ToLower(event.Status) {
	case "blocked", "sanitized", "engine_unavailable":
		return true
	}
	return strings.EqualFold(event.RiskLevel, "HIGH") || len(event.Findings) > 0
}

func (h *eventHub) publish(event inspectionEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.seq++
	event.Seq = h.seq

	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
		event.Timestamp = ts
	}
	minuteKey := (ts.UTC().Unix() / 60) * 60000
	bucket, ok := h.buckets[minuteKey]
	if !ok {
		bucket = &minuteBucket{Minute: minuteKey}
		h.buckets[minuteKey] = bucket
	}
	if isAlertEvent(event) {
		h.alertCount++
		bucket.Alerts++
	} else {
		h.cleanCount++
		bucket.Clean++
	}

	cutoff := ((time.Now().UTC().Unix() / 60) - bucketRetentionMins) * 60000
	for k := range h.buckets {
		if k < cutoff {
			delete(h.buckets, k)
		}
	}

	h.history = append(h.history, event)
	if len(h.history) > maxHistoryEvents {
		h.history = h.history[len(h.history)-maxHistoryEvents:]
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("encode SSE event: %v", err)
		return
	}
	for subscriber := range h.subscribers {
		select {
		case subscriber <- data:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- data:
			default:
			}
		}
	}
}

func (h *eventHub) snapshot(currentMode string) dashboardState {
	h.mu.RLock()
	defer h.mu.RUnlock()

	cutoff := ((time.Now().UTC().Unix() / 60) - bucketRetentionMins) * 60000
	buckets := make([]minuteBucket, 0, len(h.buckets))
	for _, b := range h.buckets {
		if b.Minute >= cutoff {
			buckets = append(buckets, *b)
		}
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Minute < buckets[j].Minute
	})

	events := make([]inspectionEvent, len(h.history))
	for i := range h.history {
		events[i] = h.history[len(h.history)-1-i]
	}

	return dashboardState{
		Mode:       currentMode,
		Seq:        h.seq,
		CleanCount: h.cleanCount,
		AlertCount: h.alertCount,
		Buckets:    buckets,
		Events:     events,
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	mode, err := configuredMode()
	if err != nil {
		return err
	}
	policy, err := configuredFailurePolicy()
	if err != nil {
		return err
	}
	socketPath := os.Getenv("PROXYGO_SOCK_PATH")
	if socketPath == "" {
		socketPath = defaultSocketPath
	}
	proxyAddr := configuredAddr("PROXYGO_PROXY_ADDR", "127.0.0.1:8080")
	dashAddr := configuredAddr("PROXYGO_DASH_ADDR", "127.0.0.1:8081")

	events := newEventHub()
	engine := newUDSClient(socketPath, policy, log.Default())
	modes := newActiveMode(mode)
	core := &proxyCore{engine: engine, modes: modes, events: events}
	var connect *connectHandler
	if envBool("PROXYGO_MITM_ENABLED") {
		cfg, err := configuredConnectConfig()
		if err != nil {
			return err
		}
		ca, err := newCertAuthority(cfg.caDir, cfg.caOrg)
		if err != nil {
			return fmt.Errorf("initialize CA: %w", err)
		}
		connect = newConnectHandler(ca, core, cfg, log.Default())
		log.Printf("HTTPS MITM enabled (CA org=%s dir=%s ports=%v hosts=%v)", cfg.caOrg, cfg.caDir, cfg.ports, cfg.allowedHosts)
	}
	proxy := newHTTPProxy(core, connect, proxyAddr)
	internal := newInternalServer(events, modes, dashAddr)
	servers := []*http.Server{proxy, internal}
	serveErrors := make(chan error, len(servers))
	for _, server := range servers {
		server := server
		go func() {
			serveErrors <- server.ListenAndServe()
		}()
	}
	log.Printf("ProxyGo listening on %s; internal UI and events on %s (mode=%s, policy=%s)", proxyAddr, dashAddr, mode, policy)

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var serveErr error
	completedServers := 0
	select {
	case <-shutdownSignal.Done():
	case serveErr = <-serveErrors:
		completedServers++
		if serveErr == http.ErrServerClosed {
			serveErr = nil
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var shutdownErr error
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil && shutdownErr == nil {
			shutdownErr = err
		}
	}
	if connect != nil {
		connect.closeAll()
	}
	if shutdownErr != nil {
		for _, server := range servers {
			_ = server.Close()
		}
	}

	for completedServers < len(servers) {
		if err := <-serveErrors; err != nil && err != http.ErrServerClosed && serveErr == nil {
			serveErr = err
		}
		completedServers++
	}
	if serveErr != nil {
		return fmt.Errorf("HTTP server stopped: %w", serveErr)
	}
	if shutdownErr != nil {
		return fmt.Errorf("HTTP server shutdown: %w", shutdownErr)
	}
	return nil
}

func configuredAddr(envKey, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(envKey)); value != "" {
		return value
	}
	return fallback
}

func envBool(envKey string) bool {
	value := strings.TrimSpace(os.Getenv(envKey))
	return value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
}

func configuredMode() (inspectionMode, error) {
	value := strings.ToUpper(strings.TrimSpace(os.Getenv("PROXYGO_MODE")))
	if value == "" {
		return modeMonitor, nil
	}
	mode := inspectionMode(value)
	switch mode {
	case modeMonitor, modeSanitize, modeBlock:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid PROXYGO_MODE %q", value)
	}
}

func configuredFailurePolicy() (FailurePolicy, error) {
	value := strings.ToUpper(strings.TrimSpace(os.Getenv("PROXYGO_FAILURE_POLICY")))
	if value == "" {
		return FailOpen, nil
	}
	policy := FailurePolicy(value)
	if policy != FailOpen && policy != FailClosed {
		return "", fmt.Errorf("invalid PROXYGO_FAILURE_POLICY %q", value)
	}
	return policy, nil
}

type proxyCore struct {
	engine *udsClient
	modes  *activeMode
	events *eventHub
}

func newHTTPProxy(core *proxyCore, connect *connectHandler, addr string) *http.Server {
	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			target := *request.In.URL
			request.SetURL(&target)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("upstream proxy error: %v", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if connect == nil {
				http.Error(w, "CONNECT tunneling is not supported", http.StatusNotImplemented)
				return
			}
			connect.serve(w, r)
			return
		}
		if r.URL.Scheme == "" || r.URL.Host == "" {
			http.Error(w, "proxy requires an absolute HTTP URL", http.StatusBadRequest)
			return
		}
		if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
			http.Error(w, "unsupported URL scheme", http.StatusBadRequest)
			return
		}

		if !core.inspect(w, r, r.URL.Hostname()) {
			return
		}
		reverseProxy.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func (p *proxyCore) inspect(w http.ResponseWriter, r *http.Request, host string) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return true
	}
	mode := p.modes.current()
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return false
		}
	}
	resetRequestBody(r, body)
	response, inspectErr := p.engine.Inspect(r.Context(), r.Method, host, body)
	if inspectErr != nil {
		p.events.publish(inspectionEvent{
			Timestamp: time.Now().UTC(), Method: r.Method, Host: host,
			Mode: string(mode), Status: "engine_unavailable",
		})
		http.Error(w, "inspection engine unavailable", http.StatusServiceUnavailable)
		return false
	}
	if response == nil {
		p.events.publish(inspectionEvent{
			Timestamp: time.Now().UTC(), Method: r.Method, Host: host,
			Mode: string(mode), Status: "fail_open",
		})
		return true
	}

	hasFindings := len(response.Findings) > 0 || strings.EqualFold(response.RiskLevel, "HIGH")
	status := "passed"
	if mode == modeBlock && hasFindings {
		status = "blocked"
	} else if mode == modeSanitize && hasFindings {
		status = "sanitized"
	}
	bodyPreview, bodyTruncated := eventBodyPreview(response.SanitizedBody)
	p.events.publish(inspectionEvent{
		ID: response.ID, Timestamp: time.Now().UTC(), Method: r.Method,
		Host: host, Mode: string(mode), Status: status,
		Category: response.Category, RiskLevel: response.RiskLevel,
		Findings:      response.Findings,
		SanitizedBody: bodyPreview, BodyTruncated: bodyTruncated,
	})

	if mode == modeBlock && hasFindings {
		http.Error(w, "request blocked by DLP policy", http.StatusForbidden)
		return false
	}
	if mode == modeSanitize && hasFindings {
		resetRequestBody(r, []byte(response.SanitizedBody))
	}
	return true
}

func resetRequestBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Expect")
}

func newInternalServer(events *eventHub, modes *activeMode, addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(events.snapshot(string(modes.current())))
	})
	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{"mode": string(modes.current())})
		case http.MethodPost:
			var request struct {
				Mode inspectionMode `json:"mode"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1024)
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				http.Error(w, "invalid mode request", http.StatusBadRequest)
				return
			}
			if request.Mode != modeMonitor && request.Mode != modeSanitize && request.Mode != modeBlock {
				http.Error(w, "mode must be MONITOR, SANITIZE, or BLOCK", http.StatusBadRequest)
				return
			}
			modes.set(request.Mode)
			_ = json.NewEncoder(w).Encode(map[string]string{"mode": string(request.Mode)})
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		subscriber, ok := events.subscribe()
		if !ok {
			http.Error(w, "too many event subscribers", http.StatusServiceUnavailable)
			return
		}
		defer events.unsubscribe(subscriber)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		fmt.Fprint(w, ": connected\n\n")
		flusher.Flush()

		heartbeat := time.NewTicker(20 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case event, open := <-subscriber:
				if !open {
					return
				}
				if _, err := fmt.Fprintf(w, "data: %s\n\n", event); err != nil {
					return
				}
				flusher.Flush()
			case <-heartbeat.C:
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})
	fileServer := http.FileServer(http.FS(web.Assets))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func eventBodyPreview(body string) (string, bool) {
	if len(body) <= maxEventBodyBytes {
		return body, false
	}
	end := maxEventBodyBytes
	for end > 0 && !utf8.RuneStart(body[end]) {
		end--
	}
	return body[:end], true
}
