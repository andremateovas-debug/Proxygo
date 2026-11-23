package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	adminTokenEnv         = "PROXYGO_ADMIN_TOKEN"
	adminTokenFileEnv     = "PROXYGO_ADMIN_TOKEN_FILE"
	defaultAdminTokenFile = "/var/lib/proxygo/admin.token"
	adminTokenBytes       = 32
	maxAdminTokenBytes    = 4096
)

type adminAuthenticator struct {
	tokenHash [sha256.Size]byte
	explicit  bool
}

func newAdminAuthenticator(token string, explicit bool) (*adminAuthenticator, error) {
	if len(token) < adminTokenBytes || token != strings.TrimSpace(token) || strings.ContainsAny(token, " \t\r\n") {
		return nil, fmt.Errorf("administrative token must contain at least %d non-whitespace bytes", adminTokenBytes)
	}
	return &adminAuthenticator{tokenHash: sha256.Sum256([]byte(token)), explicit: explicit}, nil
}

func loadAdminAuthenticator() (*adminAuthenticator, error) {
	if token, configured := os.LookupEnv(adminTokenEnv); configured && token != "" {
		return newAdminAuthenticator(token, true)
	}

	tokenFile, configuredFile := os.LookupEnv(adminTokenFileEnv)
	if strings.TrimSpace(tokenFile) == "" {
		tokenFile = defaultAdminTokenFile
		configuredFile = false
	} else {
		tokenFile = strings.TrimSpace(tokenFile)
	}
	token, err := loadOrCreateAdminToken(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("configure administrative authentication: %w", err)
	}
	return newAdminAuthenticator(token, configuredFile)
}

func loadOrCreateAdminToken(path string) (string, error) {
	token, err := readAdminTokenFile(path)
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	secret := make([]byte, adminTokenBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", errors.New("could not generate administrative token")
	}
	token = base64.RawURLEncoding.EncodeToString(secret)

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return readAdminTokenFile(path)
	}
	if err != nil {
		return "", err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if _, err := io.WriteString(file, token+"\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return token, nil
}

func readAdminTokenFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("administrative token file must be regular and private (0600 or stricter)")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxAdminTokenBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxAdminTokenBytes {
		return "", errors.New("administrative token file is too large")
	}
	token := strings.TrimSuffix(string(data), "\n")
	token = strings.TrimSuffix(token, "\r")
	if _, err := newAdminAuthenticator(token, false); err != nil {
		return "", errors.New("administrative token file contains an invalid token")
	}
	return token, nil
}

func (a *adminAuthenticator) authorize(w http.ResponseWriter, r *http.Request) bool {
	if a == nil {
		http.Error(w, "administrative authentication unavailable", http.StatusInternalServerError)
		return false
	}
	if !sameOriginRequest(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return false
	}
	authorization := r.Header.Values("Authorization")
	if len(authorization) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="proxygo-admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	scheme, token, ok := strings.Cut(authorization[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="proxygo-admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	tokenHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(tokenHash[:], a.tokenHash[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="proxygo-admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func sameOriginRequest(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) != 1 {
		return false
	}
	origin, err := url.Parse(origins[0])
	if err != nil || origin.User != nil || origin.Host == "" || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return strings.EqualFold(origin.Scheme, scheme) && strings.EqualFold(origin.Host, r.Host)
}

func validateDashboardAddress(address string, auth *adminAuthenticator) error {
	loopback, err := dashboardAddressIsLoopback(address)
	if err != nil {
		return err
	}
	if loopback {
		return nil
	}
	if auth == nil || !auth.explicit {
		return errors.New("non-loopback dashboard addresses require an explicitly configured PROXYGO_ADMIN_TOKEN or PROXYGO_ADMIN_TOKEN_FILE")
	}
	return nil
}

func dashboardAddressIsLoopback(address string) (bool, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false, fmt.Errorf("invalid PROXYGO_DASH_ADDR: %w", err)
	}
	if host == "localhost" || host == "localhost." {
		return true, nil
	}
	ip, err := netip.ParseAddr(host)
	if err == nil && ip.IsLoopback() {
		return true, nil
	}
	return false, nil
}
