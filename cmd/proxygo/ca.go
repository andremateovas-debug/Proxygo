package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	defaultCADir     = "/var/lib/proxygo/ca"
	defaultCAOrg     = "ProxyGo"
	caValidity       = 10 * 365 * 24 * time.Hour
	leafValidity     = 24 * time.Hour
	maxLeafCertCache = 1024
)

type certAuthority struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	leafKey  *ecdsa.PrivateKey
	mu       sync.Mutex
	leafs    map[string]*tls.Certificate
	cacheMax int
}

func newCertAuthority(dir, org string) (*certAuthority, error) {
	if dir == "" {
		return nil, errors.New("CA directory is empty")
	}
	if org == "" {
		org = defaultCAOrg
	}
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return nil, fmt.Errorf("CA path %s is not a directory", dir)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("CA directory %s must not be accessible by group or others (chmod 700)", dir)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create CA directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("secure CA directory: %w", err)
		}
	} else {
		return nil, fmt.Errorf("inspect CA directory: %w", err)
	}

	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")
	keyExists, err := pathExists(keyPath)
	if err != nil {
		return nil, err
	}
	certExists, err := pathExists(certPath)
	if err != nil {
		return nil, err
	}
	if keyExists != certExists {
		return nil, errors.New("incomplete CA: ca.key and ca.crt must both exist")
	}
	if !keyExists {
		if err := createCAFiles(certPath, keyPath, org); err != nil {
			return nil, err
		}
	}

	cert, key, err := loadCA(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	return &certAuthority{
		cert:     cert,
		key:      key,
		leafKey:  leafKey,
		leafs:    make(map[string]*tls.Certificate),
		cacheMax: maxLeafCertCache,
	}, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func createCAFiles(certPath, keyPath, org string) error {
	cert, key, err := generateCA(org)
	if err != nil {
		return err
	}
	keyPEM, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	if err := writeExclusive(keyPath, keyBlock, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	if err := writeExclusive(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return fmt.Errorf("write CA certificate: %w", err)
	}
	return nil
}

func generateCA(org string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	commonName := org + " Root CA"
	if len(commonName) > 64 {
		commonName = commonName[:64]
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{org}, CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return nil, nil, fmt.Errorf("secure CA key: %w", err)
	}
	if err := os.Chmod(certPath, 0o644); err != nil {
		return nil, nil, fmt.Errorf("set CA certificate permissions: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("CA certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, nil, errors.New("CA key is not an EC private key in PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	if err := validateCA(cert, key); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func validateCA(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	now := time.Now()
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("CA certificate lacks CA constraints or cert-sign usage")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("CA certificate is not currently valid")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-256" || !key.PublicKey.Equal(pub) {
		return errors.New("CA key does not match the P-256 certificate")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("CA certificate lacks CRL-sign usage")
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return errors.New("CA certificate is not signed with ECDSA SHA-256")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("CA certificate self-signature is invalid: %w", err)
	}
	return nil
}

func (a *certAuthority) certificateForHost(rawHost string) (*tls.Certificate, error) {
	host, err := normalizeHost(rawHost)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cert, ok := a.leafs[host]; ok {
		return cert, nil
	}
	if len(a.leafs) >= a.cacheMax {
		// shortcut: dropping the whole cache is fine for the expected host count; replace with an LRU if this ever churns.
		a.leafs = make(map[string]*tls.Certificate)
	}
	cert, err := a.newLeaf(host)
	if err != nil {
		return nil, err
	}
	a.leafs[host] = cert
	return cert, nil
}

func (a *certAuthority) newLeaf(host string) (*tls.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	commonName := host
	if len(commonName) > 64 {
		commonName = commonName[:64]
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("sign certificate for %s: %w", host, err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.leafKey}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return serial, nil
}

func writeExclusive(path string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := os.Chmod(path, perm); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
