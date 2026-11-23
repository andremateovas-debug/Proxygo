package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	connectSetupTimeout          = 10 * time.Second
	connectHandshakeTimeout      = 10 * time.Second
	connectDialTimeout           = 10 * time.Second
	connectTLSHandshakeTimeout   = 10 * time.Second
	connectResponseHeaderTimeout = 30 * time.Second
	connectIdleTimeout           = 60 * time.Second
	defaultConnectMax            = 128
)

var (
	errConnectBadRequest = errors.New("invalid CONNECT target")
	errConnectForbidden  = errors.New("CONNECT target forbidden")
	errBlockedAddress    = errors.New("destination address is not public")
	blockedPrefixes      = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("2001::/32"),
		netip.MustParsePrefix("2001:2::/48"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

type connectConfig struct {
	ports        map[int]struct{}
	allowedHosts []string
	maxTunnels   int
	caDir        string
	caOrg        string
}

type connectHandler struct {
	ca      *certAuthority
	core    *proxyCore
	cfg     connectConfig
	logger  *log.Logger
	sem     chan struct{}
	resolve func(context.Context, string) ([]netip.Addr, error)
	mu      sync.Mutex
	tunnels map[net.Conn]struct{}
}

func configuredConnectConfig() (connectConfig, error) {
	ports, err := parseConnectPorts(os.Getenv("PROXYGO_CONNECT_PORTS"))
	if err != nil {
		return connectConfig{}, err
	}
	hosts := parseAllowedHosts(os.Getenv("PROXYGO_CONNECT_ALLOWED_HOSTS"))
	if len(hosts) == 0 {
		return connectConfig{}, errors.New("PROXYGO_CONNECT_ALLOWED_HOSTS must list at least one host or * when MITM is enabled")
	}
	maxTunnels, err := parseConnectMax(os.Getenv("PROXYGO_CONNECT_MAX"))
	if err != nil {
		return connectConfig{}, err
	}
	caDir := strings.TrimSpace(os.Getenv("PROXYGO_CA_DIR"))
	if caDir == "" {
		caDir = defaultCADir
	}
	caOrg := strings.TrimSpace(os.Getenv("PROXYGO_CA_ORG"))
	if caOrg == "" {
		caOrg = defaultCAOrg
	}
	return connectConfig{
		ports:        ports,
		allowedHosts: hosts,
		maxTunnels:   maxTunnels,
		caDir:        caDir,
		caOrg:        caOrg,
	}, nil
}

func parseConnectPorts(value string) (map[int]struct{}, error) {
	if strings.TrimSpace(value) == "" {
		value = "443"
	}
	ports := make(map[int]struct{})
	for _, part := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid PROXYGO_CONNECT_PORTS %q", value)
		}
		ports[port] = struct{}{}
	}
	return ports, nil
}

func parseConnectMax(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return defaultConnectMax, nil
	}
	maxTunnels, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || maxTunnels < 1 || maxTunnels > 10000 {
		return 0, fmt.Errorf("invalid PROXYGO_CONNECT_MAX %q", value)
	}
	return maxTunnels, nil
}

func parseAllowedHosts(value string) []string {
	var hosts []string
	for _, part := range strings.Split(value, ",") {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(part), "."))
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func newConnectHandler(ca *certAuthority, core *proxyCore, cfg connectConfig, logger *log.Logger) *connectHandler {
	if logger == nil {
		logger = log.Default()
	}
	return &connectHandler{
		ca:      ca,
		core:    core,
		cfg:     cfg,
		logger:  logger,
		sem:     make(chan struct{}, cfg.maxTunnels),
		resolve: resolvePublic,
		tunnels: make(map[net.Conn]struct{}),
	}
}

func (h *connectHandler) serve(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	host, port, err := parseConnectTarget(authority, h.cfg)
	if err != nil {
		h.logger.Printf("connect %q: rejected: %v", authority, err)
		status := http.StatusForbidden
		if errors.Is(err, errConnectBadRequest) {
			status = http.StatusBadRequest
		}
		http.Error(w, "CONNECT target rejected", status)
		return
	}

	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		h.logger.Printf("connect %s: rejected: too many tunnels", authority)
		http.Error(w, "too many CONNECT tunnels", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), connectSetupTimeout)
	defer cancel()
	addresses, err := h.resolve(ctx, host)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errBlockedAddress) {
			status = http.StatusForbidden
		}
		h.logger.Printf("connect %s: resolve: %v", authority, err)
		http.Error(w, "CONNECT destination rejected", status)
		return
	}
	cert, err := h.ca.certificateForHost(host)
	if err != nil {
		h.logger.Printf("connect %s: certificate: %v", authority, err)
		http.Error(w, "cannot issue certificate", http.StatusInternalServerError)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT hijacking unsupported", http.StatusInternalServerError)
		return
	}
	rawConn, rw, err := hijacker.Hijack()
	if err != nil {
		h.logger.Printf("connect %s: hijack: %v", authority, err)
		return
	}
	defer rawConn.Close()
	untrack := h.track(rawConn)
	defer untrack()

	if err := rawConn.SetDeadline(time.Now().Add(connectHandshakeTimeout)); err != nil {
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" {
				sni, err := normalizeHost(hello.ServerName)
				if err != nil || sni != host {
					return nil, errors.New("SNI does not match CONNECT target")
				}
			}
			return cert, nil
		},
	}
	clientConn := &bufferedConn{Conn: rawConn, reader: rw.Reader}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.SetDeadline(time.Now().Add(connectHandshakeTimeout)); err != nil {
		return
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		h.logger.Printf("connect %s: TLS handshake: %v", authority, err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	h.logger.Printf("connect %s: TLS established", authority)

	transport := h.newTransport(host, port, addresses)
	defer transport.CloseIdleConnections()
	h.serveTunnel(tlsConn, host, port, transport)
}

func (h *connectHandler) newTransport(host string, port int, addresses []netip.Addr) *http.Transport {
	portText := strconv.Itoa(port)
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialPublic(ctx, network, addresses, portText)
		},
		TLSClientConfig:       &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   connectTLSHandshakeTimeout,
		ResponseHeaderTimeout: connectResponseHeaderTimeout,
		IdleConnTimeout:       connectIdleTimeout,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
	}
}

func (h *connectHandler) serveTunnel(conn net.Conn, host string, port int, transport *http.Transport) {
	authority := net.JoinHostPort(host, strconv.Itoa(port))
	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			target := &url.URL{Scheme: "https", Host: authority}
			request.SetURL(target)
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			h.logger.Printf("connect upstream %s: %v", authority, err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			h.logger.Printf("connect %s: rejected nested CONNECT", authority)
			http.Error(w, "nested CONNECT not supported", http.StatusMethodNotAllowed)
			return
		}
		if !h.core.inspect(w, r, host) {
			return
		}
		reverseProxy.ServeHTTP(w, r)
	})

	closed := make(chan struct{})
	tracked := &closeNotifyConn{Conn: conn, closed: closed}
	listener := &singleConnListener{conn: tracked, closed: closed}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       connectIdleTimeout,
		MaxHeaderBytes:    1 << 20,
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		h.logger.Printf("connect %s: tunnel serve: %v", authority, err)
	}
}

func (h *connectHandler) track(conn net.Conn) func() {
	h.mu.Lock()
	h.tunnels[conn] = struct{}{}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.tunnels, conn)
		h.mu.Unlock()
	}
}

func (h *connectHandler) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn := range h.tunnels {
		_ = conn.Close()
	}
}

func parseConnectTarget(authority string, cfg connectConfig) (string, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(authority))
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", errConnectBadRequest, err)
	}
	host, err = normalizeHost(host)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", errConnectBadRequest, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%w: invalid port", errConnectBadRequest)
	}
	if _, ok := cfg.ports[port]; !ok {
		return "", 0, fmt.Errorf("%w: port %d", errConnectForbidden, port)
	}
	if !hostAllowed(host, cfg.allowedHosts) {
		return "", 0, fmt.Errorf("%w: host %s", errConnectForbidden, host)
	}
	return host, port, nil
}

func normalizeHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" {
		return "", errors.New("host is empty")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", errors.New("IPv6 zones are not supported")
		}
		return addr.Unmap().String(), nil
	}
	if !validDNSName(host) {
		return "", fmt.Errorf("invalid host %q", raw)
	}
	return host, nil
}

func validDNSName(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func hostAllowed(host string, allowed []string) bool {
	for _, pattern := range allowed {
		switch {
		case pattern == "*", pattern == host:
			return true
		case strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) && host != pattern[2:]:
			return true
		}
	}
	return false
}

func resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if !isPublicAddr(addr) {
			return nil, fmt.Errorf("%w: %s", errBlockedAddress, addr)
		}
		return []netip.Addr{addr}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("no addresses found")
	}
	public := make([]netip.Addr, 0, len(addresses))
	for _, addr := range addresses {
		addr = addr.Unmap()
		if !isPublicAddr(addr) {
			return nil, fmt.Errorf("%w: %s", errBlockedAddress, addr)
		}
		public = append(public, addr)
	}
	return public, nil
}

func isPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func dialPublic(ctx context.Context, network string, addresses []netip.Addr, port string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: connectDialTimeout}
	var lastErr error
	for _, addr := range addresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no destination address")
	}
	return nil, lastErr
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

type closeNotifyConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type singleConnListener struct {
	conn   net.Conn
	closed <-chan struct{}
	once   bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.once {
		l.once = true
		return l.conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
