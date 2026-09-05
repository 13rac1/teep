// Package testtls provides isolated system-WebPKI TLS servers for tests that
// must exercise production transports without setting custom roots or
// InsecureSkipVerify on those transports.
package testtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

const childEnv = "TEEP_TESTTLS_FALLBACK_ROOT_CHILD"

// Authority is a generated certificate authority installed as a fallback
// system root only in an isolated test subprocess.
type Authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// RunWithFallbackRoot reruns the calling top-level test in an isolated
// subprocess. In that child, fn receives an authority installed through
// x509.SetFallbackRoots. Production clients can then
// leave RootCAs nil and still complete real WebPKI handshakes to NewTLSServer.
func RunWithFallbackRoot(t *testing.T, fn func(t *testing.T, authority *Authority)) {
	t.Helper()
	if os.Getenv(childEnv) == "1" {
		authority := newAuthority(t)
		installFallbackRoot(t, authority.cert)
		fn(t, authority)
		return
	}

	name := "^" + regexp.QuoteMeta(t.Name()) + "$"
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run="+name, "-test.v") //nolint:gosec // current signed test binary
	cmd.Env = childEnvironment()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated system-WebPKI test failed: %v\n%s", err, output)
	}
}

// NewTLSServer starts a TLS server with a unique leaf certificate signed by
// authority. The caller must invoke it inside RunWithFallbackRoot.
func (a *Authority) NewTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return a.newTLSServer(t, handler, "localhost", []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, nil)
}

// NewTLSServerWithConfig applies server configuration before starting TLS.
func (a *Authority) NewTLSServerWithConfig(t *testing.T, handler http.Handler, configure func(*httptest.Server)) *httptest.Server {
	t.Helper()
	return a.newTLSServer(t, handler, "localhost", []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, configure)
}

// NewTLSServerForHost starts a TLS server whose certificate is valid for
// host. Tests can map that public-looking hostname to the local listener with
// a DialContext while retaining production WebPKI verification.
func (a *Authority) NewTLSServerForHost(t *testing.T, handler http.Handler, host string) *httptest.Server {
	t.Helper()
	if host == "" {
		t.Fatal("test TLS hostname is empty")
	}
	return a.newTLSServer(t, handler, host, nil, nil)
}

func (a *Authority) newTLSServer(t *testing.T, handler http.Handler, host string, addresses []net.IP, configure func(*httptest.Server)) *httptest.Server {
	t.Helper()
	if a == nil || a.cert == nil || a.key == nil {
		t.Fatal("test TLS authority is not initialized")
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test TLS leaf key: %v", err)
	}
	serial := randomSerial(t)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
		IPAddresses:  addresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &leafKey.PublicKey, a.key)
	if err != nil {
		t.Fatalf("sign test TLS leaf certificate: %v", err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{der, a.cert.Raw},
		PrivateKey:  leafKey,
	}

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}
	if configure != nil {
		configure(server)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newAuthority(t *testing.T) *Authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test TLS CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Teep isolated test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test TLS CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test TLS CA: %v", err)
	}
	return &Authority{cert: cert, key: key}
}

func installFallbackRoot(t *testing.T, root *x509.Certificate) {
	t.Helper()
	// Do not seed this pool with x509.SystemCertPool on macOS: a pool carrying
	// the platform-system marker can route verification back through Keychain,
	// which cannot see the generated authority. The isolated child performs no
	// unrelated network operations, so the generated authority is its complete
	// fallback system trust store.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	x509.SetFallbackRoots(roots)
}

func childEnvironment() []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+2)
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key == childEnv || key == "GODEBUG" || isProxyEnvironmentKey(key) {
			continue
		}
		out = append(out, entry)
	}
	return append(out,
		childEnv+"=1",
		"GODEBUG="+replaceGODEBUG(os.Getenv("GODEBUG"), "x509usefallbackroots", "1"),
	)
}

func isProxyEnvironmentKey(key string) bool {
	switch strings.ToUpper(key) {
	case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY":
		return true
	default:
		return false
	}
}

func replaceGODEBUG(value, key, replacement string) string {
	prefix := key + "="
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts)+1)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, prefix) {
			continue
		}
		out = append(out, part)
	}
	return strings.Join(append(out, fmt.Sprintf("%s=%s", key, replacement)), ",")
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate certificate serial: %v", err)
	}
	if serial.Sign() == 0 {
		t.Fatal("generated zero certificate serial")
	}
	return serial
}
