package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	tuiMaxEvents    = 500
	tuiRefreshEvery = 5 * time.Second
)

var (
	redactedPattern = regexpMustCompile(`\[REDACTED_[A-Z0-9_]+\]`)
	tuiAccent       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	tuiMuted        = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	tuiGreen        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	tuiRed          = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	tuiYellow       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	tuiSelected     = lipgloss.NewStyle().Reverse(true)
)

type tuiFinding struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type tuiEvent struct {
	Seq           uint64       `json:"seq"`
	Timestamp     time.Time    `json:"timestamp"`
	Method        string       `json:"method"`
	Host          string       `json:"host"`
	Mode          string       `json:"mode"`
	Status        string       `json:"status"`
	Category      string       `json:"category"`
	RiskLevel     string       `json:"risk_level"`
	Findings      []tuiFinding `json:"findings"`
	SanitizedBody string       `json:"sanitized_body"`
	Protocol      string       `json:"protocol"`
	Inspected     bool         `json:"inspected"`
}

type tuiBucket struct {
	Minute int64  `json:"minute"`
	Clean  uint64 `json:"clean"`
	Alerts uint64 `json:"alerts"`
}

type tuiCAState struct {
	CAEnabled      bool      `json:"ca_enabled"`
	CAOrganization string    `json:"ca_org"`
	CACertPath     string    `json:"ca_cert_path"`
	CANotBefore    time.Time `json:"ca_not_before"`
	CANotAfter     time.Time `json:"ca_not_after"`
}

type tuiState struct {
	Mode       string      `json:"mode"`
	Seq        uint64      `json:"seq"`
	CleanCount uint64      `json:"clean_count"`
	AlertCount uint64      `json:"alert_count"`
	Buckets    []tuiBucket `json:"buckets"`
	Events     []tuiEvent  `json:"events"`
	tuiCAState
}

type tuiModel struct {
	ctx          context.Context
	dashboardURL string
	proxyURL     string
	proxyClient  *http.Client
	streamClient *http.Client
	stream       chan tuiStreamResult
	mode         string
	ca           tuiCAState
	events       []tuiEvent
	buckets      []tuiBucket
	lastSeq      uint64
	cleanCount   uint64
	alertCount   uint64
	filter       string
	selected     int
	width        int
	height       int
	connected    bool
	busy         bool
	status       string
	statusError  bool
	overlay      string
	menuIndex    int
	testStatus   string
}

type tuiStateMsg struct {
	state tuiState
	err   error
}

type tuiModeMsg struct {
	mode string
	err  error
}

type tuiCAMsg struct {
	state tuiCAState
	err   error
}

type tuiStreamResult struct {
	event *tuiEvent
	ca    *tuiCAState
	err   error
}

type tuiTestMsg struct {
	number int
	result string
	err    error
}

type tuiTickMsg time.Time

type tuiReconnectMsg struct{}

type tuiTestCase struct {
	name string
	url  string
	body string
	tls  bool
}

var tuiTestCases = []tuiTestCase{
	{name: "Solicitud simple y segura", url: "http://httpbin.org/post", body: `{"model":"claude-3-7-sonnet","prompt":"Explica que es un Unix Domain Socket"}`},
	{name: "Fuga de API Key (Anthropic)", url: "http://httpbin.org/post", body: `{"model":"claude-3-7-sonnet","prompt":"Mi llave es sk-ant-api03-99887766554433221100aabbccddeeff"}`},
	{name: "Token JWT / Bearer anidado", url: "http://httpbin.org/post", body: `{"data":{"auth":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}}`},
	{name: "Llave AWS + alta entropía", url: "http://httpbin.org/post", body: `{"aws_key":"AKIAIOSFODNN7EXAMPLE","secret_token":"8f9d8a7s6d5f4g3h2j1k0l9z8x7c6v5b"}`},
	{name: "Inspección HTTPS MITM", url: "https://httpbin.org/post", body: `{"prompt":"llave de prueba sk-ant-api03-99887766554433221100aabbccddeeff"}`, tls: true},
}

func runTUI() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dashboardAddr := strings.TrimSpace(os.Getenv("PROXYGO_DASH_ADDR"))
	if dashboardAddr == "" {
		dashboardAddr = "127.0.0.1:8081"
	}
	proxyAddr := strings.TrimSpace(os.Getenv("PROXYGO_PROXY_ADDR"))
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:8080"
	}
	model := tuiModel{
		ctx:          ctx,
		dashboardURL: endpointURL(dashboardAddr),
		proxyURL:     endpointURL(proxyAddr),
		proxyClient:  &http.Client{Timeout: 8 * time.Second},
		streamClient: &http.Client{},
		stream:       make(chan tuiStreamResult, 32),
		mode:         "MONITOR",
		filter:       "ALL",
		status:       "Conectando al dashboard…",
	}
	program := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := program.Run()
	return err
}

func endpointURL(address string) string {
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	return strings.TrimRight(address, "/")
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(m.fetchState(), m.connectSSE(), tuiRefreshTick())
}

func tuiRefreshTick() tea.Cmd {
	return tea.Tick(tuiRefreshEvery, func(time.Time) tea.Msg { return tuiTickMsg(time.Now()) })
}

func (m tuiModel) fetchState() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.dashboardURL+"/api/state", nil)
		if err != nil {
			return tuiStateMsg{err: err}
		}
		request.Header.Set("Accept", "application/json")
		response, err := m.proxyClient.Do(request)
		if err != nil {
			return tuiStateMsg{err: err}
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return tuiStateMsg{err: fmt.Errorf("GET /api/state: %s", response.Status)}
		}
		var state tuiState
		if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&state); err != nil {
			return tuiStateMsg{err: err}
		}
		return tuiStateMsg{state: state}
	}
}

func (m tuiModel) connectSSE() tea.Cmd {
	return func() tea.Msg {
		request, err := http.NewRequestWithContext(m.ctx, http.MethodGet, m.dashboardURL+"/events", nil)
		if err != nil {
			return tuiStreamResult{err: err}
		}
		request.Header.Set("Accept", "text/event-stream")
		response, err := m.streamClient.Do(request)
		if err != nil {
			return tuiStreamResult{err: err}
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return tuiStreamResult{err: fmt.Errorf("GET /events: %s", response.Status)}
		}
		go readTUIStream(m.ctx, response.Body, m.stream)
		return tuiConnectedMsg{}
	}
}

type tuiConnectedMsg struct{}

func readTUIStream(ctx context.Context, body io.ReadCloser, output chan<- tuiStreamResult) {
	defer body.Close()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		var kind struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(data), &kind); err != nil {
			continue
		}
		result := tuiStreamResult{}
		if kind.Type == "state" {
			var state tuiCAState
			if err := json.Unmarshal([]byte(data), &state); err != nil {
				continue
			}
			result.ca = &state
		} else {
			var event tuiEvent
			if err := json.Unmarshal([]byte(data), &event); err != nil {
				continue
			}
			result.event = &event
		}
		select {
		case output <- result:
		case <-ctx.Done():
			return
		}
	}
	if err := scanner.Err(); err != nil {
		select {
		case output <- tuiStreamResult{err: err}:
		case <-ctx.Done():
		}
		return
	}
	select {
	case output <- tuiStreamResult{err: errors.New("el stream SSE se cerró")}:
	case <-ctx.Done():
	}
}

func (m tuiModel) awaitSSE() tea.Cmd {
	return func() tea.Msg {
		select {
		case result := <-m.stream:
			return result
		case <-m.ctx.Done():
			return tea.QuitMsg{}
		}
	}
}

func (m tuiModel) changeMode(mode string) tea.Cmd {
	return func() tea.Msg {
		payload, _ := json.Marshal(map[string]string{"mode": mode})
		ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.dashboardURL+"/api/mode", strings.NewReader(string(payload)))
		if err != nil {
			return tuiModeMsg{err: err}
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := m.proxyClient.Do(request)
		if err != nil {
			return tuiModeMsg{err: err}
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return tuiModeMsg{err: readAPIError(response)}
		}
		var result struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			return tuiModeMsg{err: err}
		}
		return tuiModeMsg{mode: result.Mode}
	}
}

func (m tuiModel) changeCA(enabled bool) tea.Cmd {
	return func() tea.Msg {
		payload, _ := json.Marshal(map[string]bool{"enabled": enabled})
		ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.dashboardURL+"/api/ca", strings.NewReader(string(payload)))
		if err != nil {
			return tuiCAMsg{err: err}
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := m.proxyClient.Do(request)
		if err != nil {
			return tuiCAMsg{err: err}
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return tuiCAMsg{err: readAPIError(response)}
		}
		var result tuiCAState
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			return tuiCAMsg{err: err}
		}
		return tuiCAMsg{state: result}
	}
}

func readAPIError(response *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &payload) == nil && payload.Error != "" {
		return errors.New(payload.Error)
	}
	return fmt.Errorf("%s: %s", response.Status, strings.TrimSpace(string(data)))
}

func (m tuiModel) runReaction(number int) tea.Cmd {
	return func() tea.Msg {
		if number < 1 || number > len(tuiTestCases) {
			return tuiTestMsg{number: number, err: errors.New("prueba inexistente")}
		}
		testCase := tuiTestCases[number-1]
		transport := &http.Transport{Proxy: http.ProxyURL(mustURL(m.proxyURL))}
		if testCase.tls {
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			caDir := strings.TrimSpace(os.Getenv("PROXYGO_CA_DIR"))
			if caDir == "" {
				caDir = defaultCADir
			}
			certificate, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
			if err != nil {
				return tuiTestMsg{number: number, err: fmt.Errorf("no se pudo leer ca.crt para la prueba 5: %w", err)}
			}
			if !roots.AppendCertsFromPEM(certificate) {
				return tuiTestMsg{number: number, err: errors.New("ca.crt no contiene un certificado válido")}
			}
			transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		}
		client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
		defer transport.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, testCase.url, strings.NewReader(testCase.body))
		if err != nil {
			return tuiTestMsg{number: number, err: err}
		}
		request.Header.Set("Content-Type", "application/json")
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			return tuiTestMsg{number: number, err: err}
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if readErr != nil {
			return tuiTestMsg{number: number, err: readErr}
		}
		return tuiTestMsg{number: number, result: fmt.Sprintf("%s · %s", response.Status, time.Since(started).Round(time.Millisecond))}
	}
}

func mustURL(value string) *url.URL {
	parsed, err := url.Parse(value)
	if err != nil {
		return &url.URL{Scheme: "http", Host: "127.0.0.1:8080"}
	}
	return parsed
}

func (m tuiModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
		return m, nil
	case tuiStateMsg:
		if message.err != nil {
			m.status, m.statusError = "Estado: "+message.err.Error(), true
			return m, nil
		}
		m.mode = message.state.Mode
		m.ca = message.state.tuiCAState
		m.cleanCount = message.state.CleanCount
		m.alertCount = message.state.AlertCount
		m.lastSeq = max(m.lastSeq, message.state.Seq)
		m.buckets = append([]tuiBucket(nil), message.state.Buckets...)
		m.events = mergeTUIEvents(message.state.Events, m.events)
		if len(m.events) > tuiMaxEvents {
			m.events = m.events[:tuiMaxEvents]
		}
		m.status, m.statusError = "Estado sincronizado", false
		return m, nil
	case tuiConnectedMsg:
		m.connected = true
		m.status, m.statusError = "SSE conectado", false
		return m, m.awaitSSE()
	case tuiStreamResult:
		if message.err != nil {
			m.connected = false
			m.status, m.statusError = "SSE reconectando: "+message.err.Error(), true
			return m, tea.Tick(2*time.Second, func(time.Time) tea.Msg { return tuiReconnectMsg{} })
		}
		if message.ca != nil {
			m.ca = *message.ca
		} else if message.event != nil {
			event := *message.event
			if event.Seq == 0 || event.Seq > m.lastSeq {
				m.lastSeq = max(m.lastSeq, event.Seq)
				m.events = append([]tuiEvent{event}, m.events...)
				if len(m.events) > tuiMaxEvents {
					m.events = m.events[:tuiMaxEvents]
				}
				if isTUIAlert(event) {
					m.alertCount++
				} else {
					m.cleanCount++
				}
				m.incrementBucket(event)
			}
		}
		return m, m.awaitSSE()
	case tuiModeMsg:
		m.busy = false
		if message.err != nil {
			m.status, m.statusError = "Error de modo: "+message.err.Error(), true
		} else {
			m.mode = message.mode
			m.status, m.statusError = "Modo actualizado: "+message.mode, false
		}
		return m, nil
	case tuiCAMsg:
		m.busy = false
		if message.err != nil {
			m.status, m.statusError = "Error CA: "+message.err.Error(), true
		} else {
			m.ca = message.state
			m.status, m.statusError = "MITM actualizado", false
		}
		return m, nil
	case tuiTestMsg:
		m.busy = false
		if message.err != nil {
			m.testStatus = fmt.Sprintf("Prueba %d: error: %v", message.number, message.err)
		} else {
			m.testStatus = fmt.Sprintf("Prueba %d: %s", message.number, message.result)
		}
		return m, nil
	case tuiTickMsg:
		return m, tea.Batch(m.fetchState(), tuiRefreshTick())
	case tuiReconnectMsg:
		return m, m.connectSSE()
	case tea.KeyMsg:
		return m.handleKey(message)
	}
	return m, nil
}

func (m tuiModel) handleKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.String() == "ctrl+c" || key.String() == "q" || key.String() == "esc" {
		if m.overlay != "" {
			m.overlay = ""
			return m, nil
		}
		return m, tea.Quit
	}
	if m.overlay == "detail" {
		return m, nil
	}
	if m.overlay == "tests" {
		if key.String() == "1" || key.String() == "2" || key.String() == "3" || key.String() == "4" || key.String() == "5" {
			number := int(key.String()[0] - '0')
			m.busy = true
			m.testStatus = fmt.Sprintf("Prueba %d en curso…", number)
			return m, m.runReaction(number)
		}
		return m, nil
	}
	if m.overlay == "network" {
		if key.String() == "enter" {
			m.overlay = "menu"
		}
		return m, nil
	}
	if m.overlay == "menu" {
		switch key.String() {
		case "up", "k":
			m.menuIndex = (m.menuIndex + 11) % 12
		case "down", "j":
			m.menuIndex = (m.menuIndex + 1) % 12
		case "enter":
			return m.activateMenu()
		case "r":
			m.overlay = "tests"
		}
		return m, nil
	}
	switch key.String() {
	case "tab":
		m.overlay = "menu"
		m.menuIndex = 0
	case "r":
		m.overlay = "tests"
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
	case "down", "j":
		if m.selected+1 < len(m.filteredEvents()) {
			m.selected++
		}
	case "enter":
		if events := m.filteredEvents(); len(events) > 0 {
			m.overlay = "detail"
		}
	case "1":
		m.busy = true
		m.status, m.statusError = "Cambiando modo a MONITOR…", false
		return m, m.changeMode("MONITOR")
	case "2":
		m.busy = true
		m.status, m.statusError = "Cambiando modo a SANITIZE…", false
		return m, m.changeMode("SANITIZE")
	case "3":
		m.busy = true
		m.status, m.statusError = "Cambiando modo a BLOCK…", false
		return m, m.changeMode("BLOCK")
	}
	return m, nil
}

func (m tuiModel) activateMenu() (tea.Model, tea.Cmd) {
	switch m.menuIndex {
	case 0:
		m.busy = true
		m.status = "Actualizando CA…"
		return m, m.changeCA(!m.ca.CAEnabled)
	case 1, 2, 3:
		mode := []string{"MONITOR", "SANITIZE", "BLOCK"}[m.menuIndex-1]
		m.busy = true
		m.status = "Cambiando modo a " + mode + "…"
		return m, m.changeMode(mode)
	case 4, 5, 6, 7:
		m.filter = []string{"ALL", "HIGH", "MEDIUM", "LOW"}[m.menuIndex-4]
		m.selected = 0
		m.status = "Filtro: " + m.filter
	case 8:
		return m, m.fetchState()
	case 9:
		m.events = nil
		m.selected = 0
		m.status = "Vista local limpiada"
	case 10:
		m.overlay = "network"
		return m, nil
	case 11:
		m.overlay = "tests"
		return m, nil
	}
	m.overlay = ""
	return m, nil
}

func (m tuiModel) filteredEvents() []tuiEvent {
	filtered := make([]tuiEvent, 0, len(m.events))
	for _, event := range m.events {
		if m.filter == "ALL" || tuiRisk(event) == m.filter {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func tuiRisk(event tuiEvent) string {
	risk := strings.ToUpper(event.RiskLevel)
	if risk == "HIGH" || risk == "MEDIUM" || risk == "LOW" {
		return risk
	}
	if len(event.Findings) > 0 {
		return "HIGH"
	}
	return "LOW"
}

func isTUIAlert(event tuiEvent) bool {
	return strings.EqualFold(event.Status, "blocked") || strings.EqualFold(event.Status, "sanitized") || strings.EqualFold(event.Status, "engine_unavailable") || tuiRisk(event) == "HIGH" || len(event.Findings) > 0
}

func mergeTUIEvents(snapshot, live []tuiEvent) []tuiEvent {
	merged := make([]tuiEvent, 0, len(snapshot)+len(live))
	seen := make(map[uint64]struct{}, len(snapshot)+len(live))
	for _, events := range [][]tuiEvent{live, snapshot} {
		for _, event := range events {
			if event.Seq != 0 {
				if _, ok := seen[event.Seq]; ok {
					continue
				}
				seen[event.Seq] = struct{}{}
			}
			merged = append(merged, event)
		}
	}
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].Seq > merged[j].Seq })
	return merged
}

func (m *tuiModel) incrementBucket(event tuiEvent) {
	minute := event.Timestamp.UTC().Unix() / 60 * 60000
	for index := range m.buckets {
		if m.buckets[index].Minute == minute {
			if isTUIAlert(event) {
				m.buckets[index].Alerts++
			} else {
				m.buckets[index].Clean++
			}
			return
		}
	}
	bucket := tuiBucket{Minute: minute}
	if isTUIAlert(event) {
		bucket.Alerts = 1
	} else {
		bucket.Clean = 1
	}
	m.buckets = append(m.buckets, bucket)
}

func (m tuiModel) currentRPM() uint64 {
	minute := time.Now().UTC().Unix() / 60 * 60000
	for _, bucket := range m.buckets {
		if bucket.Minute == minute {
			return bucket.Clean + bucket.Alerts
		}
	}
	return 0
}

func (m tuiModel) View() string {
	if m.overlay != "" {
		return m.renderOverlay()
	}
	width := m.width
	if width < 24 {
		width = 80
	}
	var output strings.Builder
	connection := tuiRed.Render("● SSE OFF")
	if m.connected {
		connection = tuiGreen.Render("● SSE ON")
	}
	caState := tuiRed.Render("CA: OFF")
	if m.ca.CAEnabled {
		caState = tuiGreen.Render("CA: ON")
	}
	if width < 48 {
		connection = strings.ReplaceAll(connection, "● SSE ON", "SSE:ON")
		connection = strings.ReplaceAll(connection, "● SSE OFF", "SSE:OFF")
		caState = strings.ReplaceAll(caState, "CA: ON", "CA:ON")
		caState = strings.ReplaceAll(caState, "CA: OFF", "CA:OFF")
	}
	header := fmt.Sprintf("%s  %s  %s  %s", tuiAccent.Render("PROXYGO"), connection, m.mode, caState)
	output.WriteString(truncateANSI(header, width))
	output.WriteByte('\n')
	if m.height > 0 && m.height < 10 {
		output.WriteString(truncateANSI(tuiMuted.Render(fmt.Sprintf("Limpias %d · Alertas %d · %d/min", m.cleanCount, m.alertCount, m.currentRPM())), width))
		output.WriteByte('\n')
		if events := m.filteredEvents(); len(events) > 0 {
			event := events[min(m.selected, len(events)-1)]
			output.WriteString(truncateText(fmt.Sprintf("%s %s %s %s", event.Timestamp.Local().Format("15:04:05"), tuiRisk(event), event.Host, event.Status), width))
		} else {
			output.WriteString(truncateText("Esperando eventos…", width))
		}
		output.WriteString("\n" + tuiMuted.Render(truncateText("↑/↓ navegar · Enter detalle · Tab menú · q salir", width)))
		return output.String()
	}
	output.WriteString(truncateANSI(tuiMuted.Render(fmt.Sprintf("Proxy %s   Panel %s", m.proxyURL, m.dashboardURL)), width))
	output.WriteByte('\n')
	output.WriteString(truncateText(fmt.Sprintf("Limpias %d   Alertas %d   Tráfico/min %d   Eventos %d   Filtro %s", m.cleanCount, m.alertCount, m.currentRPM(), len(m.events), m.filter), width))
	output.WriteByte('\n')
	if m.status != "" {
		status := tuiMuted.Render(m.status)
		if m.statusError {
			status = tuiRed.Render(m.status)
		}
		output.WriteString(truncateANSI(status, width))
		output.WriteByte('\n')
	}
	output.WriteString(strings.Repeat("─", max(1, width)))
	output.WriteByte('\n')
	if width < 70 {
		output.WriteString("HORA       RIESGO  HOST / ACCIÓN\n")
	} else {
		output.WriteString(fmt.Sprintf("%-8s %-7s %-16s %-24s %-12s %s\n", "HORA", "PROTO", "CATEGORÍA", "HOST", "RIESGO", "ACCIÓN"))
	}
	output.WriteString(strings.Repeat("─", max(1, width)))
	output.WriteByte('\n')
	events := m.filteredEvents()
	rows := max(1, m.height-10)
	if m.status != "" {
		rows = max(1, rows-1)
	}
	if rows > len(events) {
		rows = len(events)
	}
	start := 0
	if m.selected >= rows && rows > 0 {
		start = m.selected - rows + 1
	}
	for index := start; index < start+rows; index++ {
		event := events[index]
		stamp := event.Timestamp.Local().Format("15:04:05")
		risk := tuiRisk(event)
		styledRisk := tuiGreen.Render(risk)
		if risk == "HIGH" {
			styledRisk = tuiRed.Render(risk)
		} else if risk == "MEDIUM" {
			styledRisk = tuiYellow.Render(risk)
		}
		action := strings.ToUpper(event.Status)
		if action == "" {
			action = "—"
		}
		var row string
		const riskPlaceholder = "\x00RISK\x00"
		if width < 70 {
			row = fmt.Sprintf("%-8s %-7s %s / %s", stamp, riskPlaceholder, truncateText(event.Host, max(4, width-31)), truncateText(action, 8))
		} else {
			row = fmt.Sprintf("%-8s %-7s %-16s %-24s %-12s %s", stamp, truncateText(event.Protocol, 7), truncateText(event.Category, 16), truncateText(event.Host, 24), riskPlaceholder, truncateText(action, max(8, width-76)))
		}
		row = strings.Replace(row, riskPlaceholder, styledRisk, 1)
		if index == m.selected {
			row = tuiSelected.Render(row)
		}
		output.WriteString(row)
		output.WriteByte('\n')
	}
	if len(events) == 0 {
		output.WriteString(tuiMuted.Render("Esperando eventos de inspección…\n"))
	}
	output.WriteString("\n" + tuiMuted.Render(truncateText("↑/↓ seleccionar · Enter detalle · 1/2/3 modo · Tab menú · r pruebas · q salir", width)))
	return output.String()
}

func (m tuiModel) renderOverlay() string {
	width := min(max(m.width-10, 16), 100)
	var title string
	var content strings.Builder
	switch m.overlay {
	case "detail":
		events := m.filteredEvents()
		if m.selected >= len(events) {
			return ""
		}
		event := events[m.selected]
		title = "DETALLE DEL EVENTO"
		content.WriteString(fmt.Sprintf("%s · %s · %s\n", event.Timestamp.Local().Format(time.RFC3339), event.Method, event.Host))
		content.WriteString(fmt.Sprintf("Categoría: %s    Riesgo: %s    Acción: %s\n", fallback(event.Category, "UNKNOWN"), tuiRisk(event), fallback(event.Status, "—")))
		content.WriteString("Hallazgos:\n")
		if len(event.Findings) == 0 {
			content.WriteString("  Ninguno\n")
		} else {
			for _, finding := range event.Findings {
				content.WriteString(fmt.Sprintf("  %s %s\n", finding.Kind, finding.Path))
			}
		}
		body := event.SanitizedBody
		if body == "" {
			body = "Sin cuerpo disponible"
		} else {
			var formatted any
			if json.Unmarshal([]byte(body), &formatted) == nil {
				if pretty, err := json.MarshalIndent(formatted, "", "  "); err == nil {
					body = string(pretty)
				}
			}
		}
		content.WriteString("\nJSON sanitizado:\n")
		content.WriteString(highlightRedacted(body))
	case "menu":
		title = "MENÚ OPERATIVO"
		items := m.menuItems()
		for index, item := range items {
			line := fmt.Sprintf(" %2d  %s", index+1, item)
			if index == m.menuIndex {
				line = tuiSelected.Render(line)
			}
			content.WriteString(line + "\n")
		}
	case "tests":
		title = "PRUEBAS DE REACCIÓN · test_de_reaccion.md"
		for index, testCase := range tuiTestCases {
			content.WriteString(fmt.Sprintf(" %d  %s\n", index+1, testCase.name))
		}
		content.WriteString("\n" + m.testStatus + "\n")
		content.WriteString("Las peticiones usan el proxy configurado y no muestran el cuerpo de respuesta.\n")
	case "network":
		title = "ENDPOINTS DE RED"
		content.WriteString("Proxy HTTP / MITM: " + m.proxyURL + "\n")
		content.WriteString("Dashboard / API / SSE: " + m.dashboardURL + "\n")
		caStatus := "INACTIVA"
		if m.ca.CAEnabled {
			caStatus = "ACTIVA"
		}
		content.WriteString("CA / MITM: " + caStatus + "\n")
		content.WriteString("Organización CA: " + fallback(m.ca.CAOrganization, "no disponible") + "\n")
		validUntil := "desconocida"
		if !m.ca.CANotAfter.IsZero() {
			validUntil = m.ca.CANotAfter.Local().Format("2006-01-02 15:04 MST")
		}
		content.WriteString("Válida hasta: " + validUntil + "\n")
		socketPath := os.Getenv("PROXYGO_SOCK_PATH")
		if socketPath == "" {
			socketPath = defaultSocket
		}
		content.WriteString("Socket UDS: " + socketPath + "\n")
		content.WriteString("Acceso remoto: " + sshTunnelNote(m.dashboardURL) + "\n")
		content.WriteString("Certificado público: " + fallback(m.ca.CACertPath, "no configurado") + "\n")
	}
	box := lipgloss.NewStyle().Width(width).MaxHeight(max(1, m.height-4)).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("39")).Padding(1, 2).Render(tuiAccent.Render(title) + "\n\n" + content.String() + "\n" + tuiMuted.Render("↑/↓ navegar · Enter seleccionar · Esc volver"))
	return lipgloss.Place(max(1, m.width), max(1, m.height), lipgloss.Center, lipgloss.Center, box)
}

func (m tuiModel) menuItems() []string {
	ca := "OFF"
	if m.ca.CAEnabled {
		ca = "ON"
	}
	caDetails := m.ca.CACertPath
	if caDetails == "" {
		caDetails = "ruta pública no disponible"
	}
	return []string{
		"CA / MITM: " + ca + " (alternar) · " + caDetails,
		"Modo MONITOR",
		"Modo SANITIZE",
		"Modo BLOCK",
		"Filtro ALL",
		"Filtro HIGH",
		"Filtro MEDIUM",
		"Filtro LOW",
		"Sincronizar estado",
		"Limpiar vista local",
		"Información de red/endpoints",
		"Controlador de pruebas (r)",
	}
}

func sshTunnelNote(dashboardURL string) string {
	port := "8081"
	if parsed, err := url.Parse(dashboardURL); err == nil && parsed.Port() != "" {
		port = parsed.Port()
	}
	return fmt.Sprintf("ssh -L %s:127.0.0.1:%s usuario@host", port, port)
}

func highlightRedacted(value string) string {
	return redactedPattern.ReplaceAllStringFunc(value, func(token string) string {
		return tuiYellow.Render(token)
	})
}

func truncateText(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	runes := []rune(value)
	return string(runes[:max(0, limit-1)]) + "…"
}

func truncateANSI(value string, limit int) string {
	if lipgloss.Width(value) <= limit {
		return value
	}
	return lipgloss.NewStyle().MaxWidth(limit).Render(value)
}

func fallback(value, alternate string) string {
	if value == "" {
		return alternate
	}
	return value
}

func regexpMustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
