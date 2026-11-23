package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"proxygo/web"
)

const (
	maxRequestBodyBytes    = 32 << 20
	maxEventBodyBytes      = 64 << 10
	maxHistoryEvents       = 500
	bucketRetentionMins    = 60
	defaultMaxBodyBytes    = 32 << 20
	maxEngineBodyBytes     = int64(maxInspectBodyBytes)
	defaultEngineTimeoutMs = 15
)

type inspectionMode string

const (
	modeMonitor  inspectionMode = "MONITOR"
	modeSanitize inspectionMode = "SANITIZE"
	modeBlock    inspectionMode = "BLOCK"
)

type securityPolicy string

const (
	AllowUninspected   securityPolicy = "ALLOW_UNINSPECTED"
	BlockUninspected   securityPolicy = "BLOCK_UNINSPECTED"
	MonitorUninspected securityPolicy = "MONITOR_UNINSPECTED"
)

type inspectionEvent struct {
	Seq              uint64            `json:"seq,omitempty"`
	ID               string            `json:"id,omitempty"`
	Timestamp        time.Time         `json:"timestamp"`
	Method           string            `json:"method"`
	Host             string            `json:"host"`
	Path             string            `json:"path,omitempty"`
	Mode             string            `json:"mode"`
	Status           string            `json:"status"`
	Category         string            `json:"category,omitempty"`
	RiskLevel        string            `json:"risk_level,omitempty"`
	Findings         []Finding         `json:"findings,omitempty"`
	SanitizedBody    string            `json:"sanitized_body,omitempty"`
	BodyTruncated    bool              `json:"body_truncated,omitempty"`
	SanitizedHeaders map[string]string `json:"sanitized_headers,omitempty"`
	Direction        string            `json:"direction,omitempty"`
	Protocol         string            `json:"protocol,omitempty"`
	Inspected        bool              `json:"inspected"`
	ConnectionType   string            `json:"connection_type,omitempty"`
	CertGenerated    bool              `json:"cert_generated,omitempty"`
	TLSError         string            `json:"tls_error,omitempty"`
	ValidationError  string            `json:"validation_error,omitempty"`
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
	caPublicState
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
	case "blocked", "sanitized", "engine_unavailable", "body_too_large", "body_read_error":
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
	h.broadcastLocked(data)
}

func (h *eventHub) publishState(state caPublicState) {
	data, err := json.Marshal(struct {
		Type string `json:"type"`
		caPublicState
	}{Type: "state", caPublicState: state})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broadcastLocked(data)
}

func (h *eventHub) broadcastLocked(data []byte) {
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

func (h *eventHub) snapshot(currentMode string, caState ...caPublicState) dashboardState {
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

	state := dashboardState{
		Mode:       currentMode,
		Seq:        h.seq,
		CleanCount: h.cleanCount,
		AlertCount: h.alertCount,
		Buckets:    buckets,
		Events:     events,
	}
	if len(caState) > 0 {
		state.caPublicState = caState[0]
	}
	return state
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
	adminAuth, err := loadAdminAuthenticator()
	if err != nil {
		return err
	}
	if err := validateDashboardAddress(dashAddr, adminAuth); err != nil {
		return err
	}
	if loopback, _ := dashboardAddressIsLoopback(dashAddr); !loopback {
		log.Printf("WARNING: dashboard is listening on non-loopback HTTP address %s; restrict network access and use a trusted encrypted channel", dashAddr)
	}

	events := newEventHub()
	engine := newUDSClient(socketPath, policy, log.Default())
	modes := newActiveMode(mode)
	core := &proxyCore{
		engine:              engine,
		modes:               modes,
		events:              events,
		securityPolicy:      configuredSecurityPolicy(),
		inspectRequests:     configuredBool("PROXYGO_INSPECT_REQUESTS", true),
		inspectResponses:    configuredBool("PROXYGO_INSPECT_RESPONSES", true),
		inspectHeadersFlag:  configuredBool("PROXYGO_INSPECT_HEADERS", true),
		blockInvalidCerts:   configuredBool("PROXYGO_BLOCK_INVALID_CERTS", true),
		blockPrivateNetwork: configuredBool("PROXYGO_BLOCK_PRIVATE_NETWORKS", true),
		maxBodyBytes:        configuredMaxBodyBytes(),
	}
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
	mitm := newMITMController(core, connect, log.Default(), events)
	core.mitm = mitm
	proxy := newHTTPProxy(core, connect, proxyAddr)
	internal := newInternalServer(events, modes, dashAddr, adminAuth, mitm)
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
	engine              *udsClient
	modes               *activeMode
	events              *eventHub
	credentials         sync.Map
	securityPolicy      securityPolicy
	inspectRequests     bool
	inspectResponses    bool
	inspectHeadersFlag  bool
	blockInvalidCerts   bool
	blockPrivateNetwork bool
	maxBodyBytes        int64
	mitm                *mitmController
}

type inspectionResult struct {
	proceed          bool
	sanitizedBody    []byte
	sanitizedHeaders map[string]string
	status           string
	event            inspectionEvent
}

type inspectionDirection string

const (
	directionRequest  inspectionDirection = "REQUEST"
	directionResponse inspectionDirection = "RESPONSE"
)

type boundedBodyRead struct {
	body      []byte
	replay    io.ReadCloser
	tooLarge  bool
	readError error
}

type readCloser struct {
	io.Reader
	io.Closer
}

type errorThenReader struct {
	err    error
	reader io.Reader
	done   bool
}

func (r *errorThenReader) Read(data []byte) (int, error) {
	if !r.done {
		r.done = true
		return 0, r.err
	}
	return r.reader.Read(data)
}

func inspectionBodyLimit(configured int64) int64 {
	if configured <= 0 {
		configured = defaultMaxBodyBytes
	}
	if configured > maxEngineBodyBytes {
		return maxEngineBodyBytes
	}
	return configured
}

func readBoundedBody(body io.ReadCloser, maxBytes int64) boundedBodyRead {
	if body == nil {
		return boundedBodyRead{}
	}

	data, readErr := io.ReadAll(io.LimitReader(body, maxBytes+1))
	result := boundedBodyRead{
		body:      data,
		tooLarge:  int64(len(data)) > maxBytes,
		readError: readErr,
	}
	if readErr != nil {
		replay := io.MultiReader(bytes.NewReader(data), &errorThenReader{err: readErr, reader: body})
		result.replay = readCloser{Reader: replay, Closer: body}
		return result
	}
	if result.tooLarge {
		result.replay = readCloser{Reader: io.MultiReader(bytes.NewReader(data), body), Closer: body}
		return result
	}

	_ = body.Close()
	result.replay = io.NopCloser(bytes.NewReader(data))
	return result
}

func incompleteBodyReason(result boundedBodyRead, maxBytes int64) (string, string) {
	if result.tooLarge {
		return "body_too_large", fmt.Sprintf("body exceeds inspection limit of %d bytes", maxBytes)
	}
	return "body_read_error", fmt.Sprintf("body read failed: %v", result.readError)
}

func (p *proxyCore) blockIncompleteBody(mode inspectionMode) bool {
	return mode == modeBlock || mode == modeSanitize
}

func setRequestBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Expect")
}

func syncRequestBodyLength(r *http.Request) {
	r.Header.Set("Content-Length", fmt.Sprint(r.ContentLength))
	r.TransferEncoding = nil
	r.Header.Del("Transfer-Encoding")
}

func setResponseBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	syncResponseBodyFraming(resp)
}

func syncResponseBodyFraming(resp *http.Response) {
	resp.TransferEncoding = nil
	resp.Header.Set("Content-Length", fmt.Sprint(resp.ContentLength))
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Range")
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
			if core.mitm != nil {
				core.mitm.serve(w, r)
				return
			}
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
	return p.inspectRequest(w, r, host)
}

func (p *proxyCore) inspectRequest(w http.ResponseWriter, r *http.Request, host string) bool {
	if !p.inspectRequests {
		p.events.publish(inspectionEvent{
			Timestamp:      time.Now().UTC(),
			Method:         r.Method,
			Host:           host,
			Path:           r.URL.Path,
			Mode:           string(p.modes.current()),
			Status:         "passed",
			Protocol:       protocolLabel(r.URL.Scheme),
			Inspected:      false,
			ConnectionType: "request",
		})
		return true
	}

	mode := p.modes.current()

	maxBytes := inspectionBodyLimit(p.maxBodyBytes)

	var body []byte
	if r.Body != nil {
		read := readBoundedBody(r.Body, maxBytes)
		r.Body = read.replay
		if read.tooLarge || read.readError != nil {
			eventStatus, reason := incompleteBodyReason(read, maxBytes)
			blocked := p.blockIncompleteBody(mode)
			if blocked {
				eventStatus = "blocked"
			}
			p.events.publish(inspectionEvent{
				Timestamp:       time.Now().UTC(),
				Method:          r.Method,
				Host:            host,
				Path:            r.URL.Path,
				Mode:            string(mode),
				Status:          eventStatus,
				Protocol:        protocolLabel(r.URL.Scheme),
				Inspected:       false,
				ConnectionType:  "request",
				ValidationError: reason,
			})
			if blocked {
				_ = r.Body.Close()
				statusCode := http.StatusBadRequest
				if read.tooLarge {
					statusCode = http.StatusRequestEntityTooLarge
				}
				http.Error(w, "request blocked: body was not fully inspected", statusCode)
				return false
			}
			return true
		}
		body = read.body
	}
	if r.Body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	headers := headerMap(r.Header)
	path := r.URL.Path
	contentType := r.Header.Get("Content-Type")

	req := InspectionRequest{
		ID:           eventID(),
		Method:       r.Method,
		Host:         host,
		Path:         path,
		Body:         string(body),
		Headers:      headers,
		Direction:    string(directionRequest),
		ConnectionID: connID(r),
		ClientID:     clientID(r),
		ContentType:  contentType,
	}

	response, inspectErr := p.engine.Inspect(r.Context(), req)
	if inspectErr != nil {
		if p.securityPolicy == BlockUninspected {
			p.events.publish(inspectionEvent{
				Timestamp:       time.Now().UTC(),
				Method:          r.Method,
				Host:            host,
				Path:            path,
				Mode:            string(mode),
				Status:          "blocked",
				Protocol:        protocolLabel(r.URL.Scheme),
				Inspected:       false,
				ConnectionType:  "request",
				ValidationError: inspectErr.Error(),
			})
			http.Error(w, "request blocked: inspection engine unavailable", http.StatusServiceUnavailable)
			return false
		}
		p.events.publish(inspectionEvent{
			Timestamp:       time.Now().UTC(),
			Method:          r.Method,
			Host:            host,
			Path:            path,
			Mode:            string(mode),
			Status:          "engine_unavailable",
			Protocol:        protocolLabel(r.URL.Scheme),
			Inspected:       false,
			ConnectionType:  "request",
			ValidationError: inspectErr.Error(),
		})
		if p.securityPolicy == MonitorUninspected {
			http.Error(w, "inspection engine unavailable", http.StatusServiceUnavailable)
			return false
		}
		return true
	}
	if response == nil {
		p.events.publish(inspectionEvent{
			Timestamp:      time.Now().UTC(),
			Method:         r.Method,
			Host:           host,
			Path:           path,
			Mode:           string(mode),
			Status:         "fail_open",
			Protocol:       protocolLabel(r.URL.Scheme),
			Inspected:      false,
			ConnectionType: "request",
		})
		return true
	}

	headerFindings, sanitizedHeaders := p.inspectHeadersFromMap(headers, host, mode)
	allFindings := append(response.Findings, headerFindings...)
	hasFindings := len(allFindings) > 0 || strings.EqualFold(response.RiskLevel, "HIGH")

	bodyReplaced := false
	headerReplaced := false
	if mode == modeBlock && hasFindings {
		http.Error(w, "request blocked by DLP policy", http.StatusForbidden)
		return false
	} else if mode == modeSanitize && hasFindings {
		if response.SanitizedBody != "" && response.SanitizedBody != string(body) {
			setRequestBody(r, []byte(response.SanitizedBody))
			bodyReplaced = true
		}
		if p.inspectHeadersFlag {
			for k, v := range sanitizedHeaders {
				if k == "Content-Encoding" || k == "Content-Length" || k == "Transfer-Encoding" {
					continue
				}
				if v == "" {
					if r.Header.Get(k) != "" {
						headerReplaced = true
					}
					r.Header.Del(k)
				} else if r.Header.Get(k) != v {
					headerReplaced = true
					r.Header.Set(k, v)
				}
			}
			if bodyReplaced {
				syncRequestBodyLength(r)
			}
		}
	}

	status := "passed"
	if mode == modeBlock && hasFindings {
		status = "blocked"
	} else if mode == modeSanitize && (bodyReplaced || headerReplaced) {
		status = "sanitized"
	}

	sanitizedPreview := ""
	bodyPreview, bodyTruncated := "", false
	if bodyReplaced {
		bodyPreview, bodyTruncated = eventBodyPreview(response.SanitizedBody)
		sanitizedPreview = bodyPreview
	}
	headerPreview := sanitizeHeaderPreview(sanitizedHeaders)
	p.events.publish(inspectionEvent{
		ID:               response.ID,
		Timestamp:        time.Now().UTC(),
		Method:           r.Method,
		Host:             host,
		Path:             path,
		Mode:             string(mode),
		Status:           status,
		Category:         response.Category,
		RiskLevel:        response.RiskLevel,
		Findings:         allFindings,
		SanitizedBody:    sanitizedPreview,
		BodyTruncated:    bodyTruncated,
		SanitizedHeaders: headerPreview,
		Direction:        string(directionRequest),
		Protocol:         protocolLabel(r.URL.Scheme),
		Inspected:        true,
		ConnectionType:   "request",
	})

	return true
}

func (p *proxyCore) inspectResponse(resp *http.Response, host string) error {
	if !p.inspectResponses {
		p.events.publish(inspectionEvent{
			Timestamp:      time.Now().UTC(),
			Method:         resp.Request.Method,
			Host:           host,
			Path:           resp.Request.URL.Path,
			Mode:           string(p.modes.current()),
			Status:         "passed",
			Protocol:       "HTTPS",
			Inspected:      false,
			ConnectionType: "response",
		})
		return nil
	}

	mode := p.modes.current()

	maxBytes := inspectionBodyLimit(p.maxBodyBytes)

	encoding, compressed := compressedResponseEncoding(resp)
	wireLimit := maxBytes
	if compressed {
		wireLimit = maxEngineBodyBytes
	}

	var body []byte
	if resp.Body != nil {
		read := readBoundedBody(resp.Body, wireLimit)
		resp.Body = read.replay
		if read.tooLarge || read.readError != nil {
			eventStatus, reason := incompleteBodyReason(read, wireLimit)
			blocked := p.blockIncompleteBody(mode)
			if blocked {
				eventStatus = "blocked"
				setResponseBody(resp, []byte("response blocked: body was not fully inspected\n"))
				resp.StatusCode = http.StatusForbidden
			}
			p.events.publish(inspectionEvent{
				Timestamp:       time.Now().UTC(),
				Method:          resp.Request.Method,
				Host:            host,
				Path:            resp.Request.URL.Path,
				Mode:            string(mode),
				Status:          eventStatus,
				Protocol:        "HTTPS",
				Inspected:       false,
				ConnectionType:  "response",
				ValidationError: reason,
			})
			return nil
		}
		body = read.body
	}

	if compressed {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if !supportedCompressedResponseEncoding(encoding) {
			incompletelyInspectedResponse(p, resp, host, "unsupported_encoding", fmt.Sprintf("unsupported Content-Encoding %q", encoding), mode)
			return nil
		}
		decompressed, tooLarge, err := decompressResponseBody(body, encoding, maxBytes)
		if tooLarge {
			incompletelyInspectedResponse(p, resp, host, "body_too_large", fmt.Sprintf("decompressed body exceeds inspection limit of %d bytes", maxBytes), mode)
			return nil
		}
		if err != nil {
			incompletelyInspectedResponse(p, resp, host, "decompression_error", fmt.Sprintf("failed to decompress %s response body: %v", encoding, err), mode)
			return nil
		}
		body = decompressed
	}

	headers := headerMap(resp.Header)
	contentType := resp.Header.Get("Content-Type")

	req := InspectionRequest{
		ID:           eventID(),
		Method:       resp.Request.Method,
		Host:         host,
		Path:         resp.Request.URL.Path,
		Body:         string(body),
		Headers:      headers,
		Direction:    string(directionResponse),
		ConnectionID: connIDFromRequest(resp.Request),
		ClientID:     clientIDFromRequest(resp.Request),
		ContentType:  contentType,
	}

	response, inspectErr := p.engine.Inspect(resp.Request.Context(), req)
	if inspectErr != nil {
		if p.securityPolicy == BlockUninspected {
			p.events.publish(inspectionEvent{
				Timestamp:       time.Now().UTC(),
				Method:          resp.Request.Method,
				Host:            host,
				Path:            resp.Request.URL.Path,
				Mode:            string(mode),
				Status:          "blocked",
				Protocol:        "HTTPS",
				Inspected:       false,
				ConnectionType:  "response",
				ValidationError: inspectErr.Error(),
			})
			return inspectErr
		}
		p.events.publish(inspectionEvent{
			Timestamp:       time.Now().UTC(),
			Method:          resp.Request.Method,
			Host:            host,
			Path:            resp.Request.URL.Path,
			Mode:            string(mode),
			Status:          "engine_unavailable",
			Protocol:        "HTTPS",
			Inspected:       false,
			ConnectionType:  "response",
			ValidationError: inspectErr.Error(),
		})
		if p.securityPolicy == MonitorUninspected {
			return inspectErr
		}
		return nil
	}
	if response == nil {
		p.events.publish(inspectionEvent{
			Timestamp:      time.Now().UTC(),
			Method:         resp.Request.Method,
			Host:           host,
			Path:           resp.Request.URL.Path,
			Mode:           string(mode),
			Status:         "fail_open",
			Protocol:       "HTTPS",
			Inspected:      false,
			ConnectionType: "response",
		})
		return nil
	}

	headerFindings, sanitizedHeaders := p.inspectHeadersFromMap(headers, host, mode)
	allFindings := append(response.Findings, headerFindings...)
	hasFindings := len(allFindings) > 0 || strings.EqualFold(response.RiskLevel, "HIGH")

	bodyReplaced := false
	headerReplaced := false
	if mode == modeBlock && hasFindings {
		resp.StatusCode = http.StatusForbidden
		setResponseBody(resp, []byte("response blocked by DLP policy\n"))
	} else if mode == modeSanitize && hasFindings {
		if response.SanitizedBody != "" && response.SanitizedBody != string(body) {
			if compressed {
				compressedBody, compressErr := compressResponseBody([]byte(response.SanitizedBody), encoding)
				if compressErr != nil {
					p.events.publish(inspectionEvent{
						Timestamp: time.Now().UTC(), Method: resp.Request.Method, Host: host, Path: resp.Request.URL.Path,
						Mode: string(mode), Status: "recompression_error", Protocol: "HTTPS", Inspected: false,
						ConnectionType: "response", ValidationError: compressErr.Error(),
					})
					return nil
				}
				setCompressedResponseBody(resp, compressedBody, encoding)
			} else {
				setResponseBody(resp, []byte(response.SanitizedBody))
			}
			bodyReplaced = true
		}
		if p.inspectHeadersFlag {
			for k, v := range sanitizedHeaders {
				if k == "Content-Encoding" || k == "Content-Length" || k == "Transfer-Encoding" {
					continue
				}
				if v == "" {
					if resp.Header.Get(k) != "" {
						headerReplaced = true
					}
					resp.Header.Del(k)
				} else if resp.Header.Get(k) != v {
					headerReplaced = true
					resp.Header.Set(k, v)
				}
			}
			if bodyReplaced && !compressed {
				syncResponseBodyFraming(resp)
			}
		}
	}

	status := "passed"
	if mode == modeBlock && hasFindings {
		status = "blocked"
	} else if mode == modeSanitize && (bodyReplaced || headerReplaced) {
		status = "sanitized"
	}

	sanitizedPreview := ""
	bodyPreview, bodyTruncated := "", false
	if bodyReplaced {
		bodyPreview, bodyTruncated = eventBodyPreview(response.SanitizedBody)
		sanitizedPreview = bodyPreview
	}
	headerPreview := sanitizeHeaderPreview(sanitizedHeaders)
	p.events.publish(inspectionEvent{
		ID:               response.ID,
		Timestamp:        time.Now().UTC(),
		Method:           resp.Request.Method,
		Host:             host,
		Path:             resp.Request.URL.Path,
		Mode:             string(mode),
		Status:           status,
		Category:         response.Category,
		RiskLevel:        response.RiskLevel,
		Findings:         allFindings,
		SanitizedBody:    sanitizedPreview,
		BodyTruncated:    bodyTruncated,
		SanitizedHeaders: headerPreview,
		Direction:        string(directionResponse),
		Protocol:         "HTTPS",
		Inspected:        true,
		ConnectionType:   "response",
	})

	return nil
}

func (p *proxyCore) inspectHeaders(r *http.Request, host string, mode inspectionMode) ([]Finding, map[string]string) {
	return p.inspectHeadersFromMap(headerMap(r.Header), host, mode)
}

func (p *proxyCore) inspectHeadersFromMap(headers map[string]string, host string, mode inspectionMode) ([]Finding, map[string]string) {
	var findings []Finding
	sanitized := make(map[string]string)

	for k, v := range headers {
		lower := strings.ToLower(k)
		sanitized[k] = v

		credential := extractCredential(lower, v)
		if credential == "" {
			continue
		}

		if firstHost, ok := p.credentials.Load(credential); ok {
			if firstHost.(string) != host {
				findings = append(findings, Finding{Kind: "CREDENTIAL_LEAK", Path: fmt.Sprintf("header.%s", lower)})
				if mode == modeSanitize {
					sanitized[k] = ""
				}
				continue
			}
		} else {
			p.credentials.Store(credential, host)
		}
	}

	return findings, sanitized
}

func extractCredential(lowerHeader string, value string) string {
	switch lowerHeader {
	case "authorization":
		if strings.HasPrefix(strings.ToLower(value), "bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
		}
		if strings.HasPrefix(strings.ToLower(value), "basic ") {
			return strings.TrimSpace(strings.TrimPrefix(value, "Basic "))
		}
		return value
	case "proxy-authorization":
		if strings.HasPrefix(strings.ToLower(value), "bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
		}
		return value
	case "x-api-key":
		return value
	default:
		if strings.HasPrefix(lowerHeader, "x-") || strings.HasPrefix(lowerHeader, "proxy-") {
			return value
		}
		return ""
	}
}

func headerMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

func sanitizeHeaderPreview(headers map[string]string) map[string]string {
	preview := make(map[string]string)
	for k, v := range headers {
		if sensitiveHeaderName(k) {
			preview[k] = "[REDACTED]"
		} else if len(v) > 128 {
			preview[k] = v[:128] + "..."
		} else {
			preview[k] = v
		}
	}
	return preview
}

func sensitiveHeaderName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" || lower == "set-cookie" {
		return true
	}
	for _, marker := range []string{"auth", "key", "token", "secret", "credential", "password", "session", "private"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func eventID() string {
	return fmt.Sprintf("evt-%d", time.Now().UnixNano())
}

func connID(r *http.Request) string {
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return ""
}

func connIDFromRequest(r *http.Request) string {
	return connID(r)
}

func clientID(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		return fmt.Sprintf("auth-%x", simpleHash(auth))
	}
	if r.RemoteAddr != "" {
		return fmt.Sprintf("ip-%s", r.RemoteAddr)
	}
	return ""
}

func clientIDFromRequest(r *http.Request) string {
	return clientID(r)
}

func simpleHash(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = h*31 + uint32(s[i])
	}
	return h
}

func isCompressed(resp *http.Response) bool {
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	return encoding != "" && encoding != "identity"
}

func resetRequestBody(r *http.Request, body []byte) {
	setRequestBody(r, body)
}

func newInternalServer(events *eventHub, modes *activeMode, addr string, adminAuth *adminAuthenticator, controllers ...*mitmController) *http.Server {
	mux := http.NewServeMux()
	var mitm *mitmController
	if len(controllers) > 0 {
		mitm = controllers[0]
	}
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		state := caPublicState{}
		if mitm != nil {
			state = mitm.publicState()
		}
		_ = json.NewEncoder(w).Encode(events.snapshot(string(modes.current()), state))
	})
	mux.HandleFunc("/api/ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method {
		case http.MethodGet:
			if mitm == nil {
				http.Error(w, "CA control unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(mitm.publicState())
		case http.MethodPost:
			if !adminAuth.authorize(w, r) {
				return
			}
			if mitm == nil {
				http.Error(w, "CA control unavailable", http.StatusServiceUnavailable)
				return
			}
			var request struct {
				Enabled *bool `json:"enabled"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1024)
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil || request.Enabled == nil {
				http.Error(w, "invalid CA request: enabled must be a boolean", http.StatusBadRequest)
				return
			}
			state, err := mitm.setEnabled(*request.Enabled)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(state)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{"mode": string(modes.current())})
		case http.MethodPost:
			if !adminAuth.authorize(w, r) {
				return
			}
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

func protocolLabel(scheme string) string {
	if scheme == "https" {
		return "HTTPS"
	}
	return "HTTP"
}

func configuredSecurityPolicy() securityPolicy {
	switch strings.ToUpper(strings.TrimSpace(os.Getenv("PROXYGO_SECURITY_POLICY"))) {
	case string(AllowUninspected):
		return AllowUninspected
	case string(BlockUninspected):
		return BlockUninspected
	case string(MonitorUninspected):
		return MonitorUninspected
	default:
		return AllowUninspected
	}
}

func configuredBool(envKey string, defaultValue bool) bool {
	value := strings.TrimSpace(os.Getenv(envKey))
	if value == "" {
		return defaultValue
	}
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func configuredMaxBodyBytes() int64 {
	value := strings.TrimSpace(os.Getenv("PROXYGO_MAX_BODY_BYTES"))
	if value == "" {
		return defaultMaxBodyBytes
	}
	if parsed, err := strconv.ParseInt(value, 10, 64); err == nil && parsed > 0 {
		return parsed
	}
	return defaultMaxBodyBytes
}

func compressedResponseEncoding(resp *http.Response) (string, bool) {
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding == "" || encoding == "identity" {
		return "", false
	}
	return encoding, true
}

func supportedCompressedResponseEncoding(encoding string) bool {
	return encoding == "gzip" || encoding == "deflate"
}

func readLimitedDecompressed(reader io.Reader, maxBytes int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if int64(len(data)) > maxBytes {
		return nil, true, nil
	}
	return data, false, err
}

func decompressResponseBody(data []byte, encoding string, maxBytes int64) ([]byte, bool, error) {
	var reader io.ReadCloser
	var err error
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(data))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			reader = io.NopCloser(flate.NewReader(bytes.NewReader(data)))
			err = nil
		}
	default:
		return nil, false, fmt.Errorf("unsupported Content-Encoding %q", encoding)
	}
	if err != nil {
		return nil, false, err
	}
	decompressed, tooLarge, readErr := readLimitedDecompressed(reader, maxBytes)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, false, readErr
	}
	if closeErr != nil {
		return nil, false, closeErr
	}
	return decompressed, tooLarge, nil
}

func compressResponseBody(data []byte, encoding string) ([]byte, error) {
	var output bytes.Buffer
	if encoding == "gzip" {
		writer := gzip.NewWriter(&output)
		if _, err := writer.Write(data); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return output.Bytes(), nil
	}
	if encoding == "deflate" {
		writer := zlib.NewWriter(&output)
		if _, err := writer.Write(data); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return output.Bytes(), nil
	}
	return nil, fmt.Errorf("unsupported Content-Encoding %q", encoding)
}

func setCompressedResponseBody(resp *http.Response, body []byte, encoding string) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Header.Set("Content-Encoding", encoding)
	resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Del("Content-Range")
	resp.Header.Del("Content-MD5")
	resp.Header.Del("Digest")
	resp.Header.Del("ETag")
}

func incompletelyInspectedResponse(p *proxyCore, resp *http.Response, host, status, reason string, mode inspectionMode) {
	blocked := p.blockIncompleteBody(mode)
	if blocked {
		status = "blocked"
		setResponseBody(resp, []byte("response blocked: body was not fully inspected\n"))
		resp.StatusCode = http.StatusForbidden
	}
	p.events.publish(inspectionEvent{
		Timestamp: time.Now().UTC(), Method: resp.Request.Method, Host: host, Path: resp.Request.URL.Path,
		Mode: string(mode), Status: status, Protocol: "HTTPS", Inspected: false,
		ConnectionType: "response", ValidationError: reason,
	})
}
