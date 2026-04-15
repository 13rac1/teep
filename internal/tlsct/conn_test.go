package tlsct_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
)

func TestNewConn_ExtractsSPKI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tc := dialTestServer(t, srv)

	conn, err := tlsct.NewConn(tc)
	if err != nil {
		_ = tc.Close()
		t.Fatalf("NewConn: %v", err)
	}
	defer conn.Close()

	spki := conn.SPKI()
	if spki == "" {
		t.Fatal("SPKI is empty")
	}
	if len(spki) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("SPKI length = %d, want 64", len(spki))
	}
	t.Logf("SPKI: %s", spki)
}

func TestNewConn_ConsistentSPKI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Two connections to the same server should produce the same SPKI.
	tc1 := dialTestServer(t, srv)
	conn1, err := tlsct.NewConn(tc1)
	if err != nil {
		t.Fatalf("NewConn 1: %v", err)
	}
	defer conn1.Close()

	tc2 := dialTestServer(t, srv)
	conn2, err := tlsct.NewConn(tc2)
	if err != nil {
		t.Fatalf("NewConn 2: %v", err)
	}
	defer conn2.Close()

	if conn1.SPKI() != conn2.SPKI() {
		t.Errorf("SPKI mismatch: %s vs %s", conn1.SPKI(), conn2.SPKI())
	}
}

func TestConn_ImplementsNetConn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tc := dialTestServer(t, srv)
	conn, err := tlsct.NewConn(tc)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	defer conn.Close()

	// Verify it satisfies net.Conn.
	var _ net.Conn = conn

	// Check deadline methods don't panic.
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}

	// Check address methods.
	if conn.LocalAddr() == nil {
		t.Error("LocalAddr is nil")
	}
	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr is nil")
	}
}

func TestTLSState_ReturnsState(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tc := dialTestServer(t, srv)
	conn, err := tlsct.NewConn(tc)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	defer conn.Close()

	state := conn.TLSState()
	if state == nil {
		t.Fatal("TLSState returned nil")
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("TLSState has no peer certificates")
	}
}

func TestTLSState_CheckerIntegration(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tc := dialTestServer(t, srv)
	conn, err := tlsct.NewConn(tc)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	defer conn.Close()

	checker := tlsct.NewChecker()
	state := conn.TLSState()

	// Use a non-private host so the result depends on checker enablement,
	// not the localhost/private-host bypass.
	const host = "example.com"

	if err := checker.CheckTLSState(context.Background(), host, state); err == nil {
		t.Fatal("CheckTLSState with enabled checker should fail for test cert")
	}

	checker.SetEnabled(false)

	// Disabled checker should return nil.
	if err := checker.CheckTLSState(context.Background(), host, state); err != nil {
		t.Errorf("CheckTLSState with disabled checker: %v", err)
	}
}

func TestDial_RefusedConnection(t *testing.T) {
	// Use a local refused connection for deterministic failure without DNS.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := tlsct.Dial(ctx, "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for refused connection")
	}
}

func TestDialAddr_InvalidAddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := tlsct.DialAddr(ctx, "example.com", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for refused connection")
	}
}

func TestDial_HostPort(t *testing.T) {
	// Dial with host:port should not double-append :443.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := tlsct.Dial(ctx, "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for refused connection")
	}
	// Should NOT contain ":1:443" — that would indicate double-port.
	if strings.Contains(err.Error(), ":1:443") {
		t.Errorf("Dial appended :443 to host:port: %v", err)
	}
}

func TestDial_IPv6Literal(t *testing.T) {
	// Bare IPv6 literal should get brackets and :443, not produce a malformed address.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := tlsct.Dial(ctx, "::1")
	if err == nil {
		t.Fatal("expected error for refused connection")
	}
	// Error should reference [::1]:443, not a malformed ::1:443.
	if strings.Contains(err.Error(), "::1:443") && !strings.Contains(err.Error(), "[::1]:443") {
		t.Errorf("Dial produced malformed IPv6 address: %v", err)
	}
}

func TestDial_MalformedHost(t *testing.T) {
	_, err := tlsct.Dial(context.Background(), "host:port:extra")
	if err == nil {
		t.Fatal("expected error for malformed host")
	}
}

func TestDial_BracketedIPv6(t *testing.T) {
	// "[::1]" should be normalized to "::1" for SNI, not double-bracketed.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := tlsct.Dial(ctx, "[::1]")
	if err == nil {
		t.Fatal("expected error for refused connection")
	}
	// Must not contain "[[" which indicates double-bracketing.
	if strings.Contains(err.Error(), "[[") {
		t.Errorf("Dial double-bracketed IPv6: %v", err)
	}
}

func TestDial_BracketValidation(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string // substring expected in error
	}{
		{"unbalanced leading", "[::1", "unbalanced brackets"},
		{"unbalanced trailing", "::1]", "unbalanced brackets"},
		{"bracketed hostname", "[example.com]", "bracketed host must be an IPv6 literal"},
		{"bracketed hostname with port", "[example.com]:443", "bracketed host must be an IPv6 literal"},
		{"nested brackets", "[[::1]]", "malformed brackets"},
		{"embedded bracket", "exam[ple", "malformed brackets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tlsct.Dial(context.Background(), tt.host)
			if err == nil {
				t.Fatalf("Dial(%q) = nil, want error", tt.host)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Dial(%q) error = %v, want substring %q", tt.host, err, tt.want)
			}
		})
	}
}

func TestDial_TrailingColon(t *testing.T) {
	_, err := tlsct.Dial(context.Background(), "example.com:")
	if err == nil {
		t.Fatal("expected error for trailing colon (empty port)")
	}
}

func TestDial_EmptyHostWithPort(t *testing.T) {
	_, err := tlsct.Dial(context.Background(), ":443")
	if err == nil {
		t.Fatal("expected error for empty host with port")
	}
	if !strings.Contains(err.Error(), "empty host") {
		t.Errorf("expected 'empty host' error, got: %v", err)
	}
}

func TestDialAddr_EmptyServerName(t *testing.T) {
	_, err := tlsct.DialAddr(context.Background(), "", "127.0.0.1:443")
	if err == nil {
		t.Fatal("expected error for empty serverName")
	}
}

// dialTestServer dials an httptest.TLSServer and returns a raw *tls.Conn.
func dialTestServer(t *testing.T, srv *httptest.Server) *tls.Conn {
	t.Helper()
	certPool := x509.NewCertPool()
	certPool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	return conn
}
