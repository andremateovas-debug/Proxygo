package main

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertAuthorityCreatesAndReloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, err := newCertAuthority(dir, "Test Org")
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ca.key permissions = %04o, want 0600", perm)
	}
	if info, err := os.Stat(filepath.Join(dir, "ca.crt")); err != nil {
		t.Fatal(err)
	} else if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("ca.crt permissions = %04o, want 0644", perm)
	}
	if info, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("CA directory permissions = %04o, want 0700", perm)
	}
	if len(ca.cert.Subject.Organization) != 1 || ca.cert.Subject.Organization[0] != "Test Org" {
		t.Fatalf("CA organization = %v, want Test Org", ca.cert.Subject.Organization)
	}

	reloaded, err := newCertAuthority(dir, "Other Org")
	if err != nil {
		t.Fatal(err)
	}
	if string(reloaded.cert.Raw) != string(ca.cert.Raw) {
		t.Fatal("reloading the CA changed the certificate")
	}
	if len(reloaded.cert.Subject.Organization) != 1 || reloaded.cert.Subject.Organization[0] != "Test Org" {
		t.Fatalf("reloaded CA organization = %v, want Test Org", reloaded.cert.Subject.Organization)
	}
}

func TestCertAuthorityIssuesLeafWithSAN(t *testing.T) {
	ca := newTestCA(t)
	issued, err := ca.certificateForHost("Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(issued.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Fatalf("leaf DNS SANs = %v, want [example.com]", leaf.DNSNames)
	}
	if leaf.IsCA {
		t.Fatal("leaf certificate is marked as a CA")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("leaf certificate lacks digital-signature usage")
	}
	if err := leaf.CheckSignatureFrom(ca.cert); err != nil {
		t.Fatalf("leaf is not signed by the CA: %v", err)
	}
	if leaf.NotAfter.After(time.Now().Add(leafValidity + time.Hour)) {
		t.Fatalf("leaf validity is longer than expected: %s", leaf.NotAfter)
	}
	cached, err := ca.certificateForHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cached != issued {
		t.Fatal("same host was regenerated instead of using the cache")
	}
}

func TestCertAuthorityIssuesIPLeaf(t *testing.T) {
	ca := newTestCA(t)
	issued, err := ca.certificateForHost("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(issued.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("leaf IP SANs = %v, want [8.8.8.8]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Fatalf("IP leaf has unexpected DNS SANs: %v", leaf.DNSNames)
	}
}

func TestCertAuthorityRejectsInvalidHosts(t *testing.T) {
	ca := newTestCA(t)
	for _, host := range []string{"", "bad host", "a..b", "-bad.com", "bad-.com", "bad/host"} {
		if _, err := ca.certificateForHost(host); err == nil {
			t.Fatalf("host %q was accepted", host)
		}
	}
}

func TestValidateCARejectsLeaf(t *testing.T) {
	ca := newTestCA(t)
	issued, err := ca.certificateForHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(issued.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCA(leaf, ca.leafKey); err == nil {
		t.Fatal("validateCA accepted a non-CA certificate")
	}
}

func newTestCA(t *testing.T) *certAuthority {
	t.Helper()
	ca, err := newCertAuthority(filepath.Join(t.TempDir(), "ca"), "Test Org")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestCertAuthorityRejectsOpenDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newCertAuthority(dir, "Test Org"); err == nil {
		t.Fatal("CA directory accessible by group or others was accepted")
	}
}
