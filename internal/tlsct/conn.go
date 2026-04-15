package tlsct

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	// DefaultDialTimeout is the TCP+TLS handshake timeout for pinned connections.
	DefaultDialTimeout = 30 * time.Second
)

// Conn wraps a TLS connection with pre-computed SPKI fingerprint. It
// implements net.Conn so callers can use it with bufio readers/writers
// without importing crypto/tls directly.
//
// The SPKI hash is extracted once during creation and cached for the
// lifetime of the connection.
type Conn struct {
	inner    *tls.Conn
	spki     string
	tlsState tls.ConnectionState
}

// Dial opens a TLS 1.3 connection to the given host with standard CA chain
// validation. If host contains a port (host:port), it is used as-is;
// otherwise :443 is appended. The host (without port) is used as the TLS
// ServerName for SNI and certificate verification.
func Dial(ctx context.Context, host string) (*Conn, error) {
	h, p, err := net.SplitHostPort(host)
	if err == nil {
		return DialAddr(ctx, h, net.JoinHostPort(h, p))
	}

	// Distinguish "missing port" (bare hostname) from genuinely malformed
	// input. Also accept bare IP addresses (including IPv6 literals).
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" || net.ParseIP(host) != nil {
		return DialAddr(ctx, host, net.JoinHostPort(host, "443"))
	}

	return nil, fmt.Errorf("invalid host %q: %w", host, err)
}

// DialAddr opens a TLS 1.3 connection to addr with the given serverName
// for SNI and certificate verification. The SPKI hash is extracted from
// the peer certificate after the handshake completes.
func DialAddr(ctx context.Context, serverName, addr string) (*Conn, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: DefaultDialTimeout},
		Config: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS13,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("tls.Dialer returned %T, expected *tls.Conn", conn)
	}
	return newConn(tc)
}

// NewConn wraps an existing *tls.Conn into a tlsct.Conn, extracting the
// SPKI hash from the peer certificate. The handshake must already be complete.
// This is intended for tests that create connections to httptest.TLSServer
// with custom root CAs.
func NewConn(tc *tls.Conn) (*Conn, error) {
	return newConn(tc)
}

func newConn(tc *tls.Conn) (*Conn, error) {
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		tc.Close()
		return nil, errors.New("no peer certificate from server")
	}
	spki, err := computeSPKIHash(state.PeerCertificates[0].Raw)
	if err != nil {
		tc.Close()
		return nil, fmt.Errorf("compute SPKI hash: %w", err)
	}
	return &Conn{inner: tc, spki: spki, tlsState: state}, nil
}

// computeSPKIHash returns the lowercase hex SHA-256 of a DER certificate's
// SubjectPublicKeyInfo.
func computeSPKIHash(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:]), nil
}

// SPKI returns the SHA-256 hex fingerprint of the peer certificate's
// SubjectPublicKeyInfo, computed at connection creation time.
func (c *Conn) SPKI() string { return c.spki }

// CheckCT verifies that the peer certificate chain provides valid SCT
// evidence anchored to a known CT log. Returns nil if the checker is nil
// or disabled.
func (c *Conn) CheckCT(ctx context.Context, host string, checker *Checker) error {
	if checker == nil {
		return nil
	}
	return checker.CheckTLSState(ctx, host, &c.tlsState)
}

// net.Conn implementation — delegates to the underlying *tls.Conn.

func (c *Conn) Read(b []byte) (int, error)  { return c.inner.Read(b) }
func (c *Conn) Write(b []byte) (int, error) { return c.inner.Write(b) }
func (c *Conn) Close() error                { return c.inner.Close() }      //nolint:revive // net.Conn delegation
func (c *Conn) LocalAddr() net.Addr         { return c.inner.LocalAddr() }  //nolint:revive // net.Conn delegation
func (c *Conn) RemoteAddr() net.Addr        { return c.inner.RemoteAddr() } //nolint:revive // net.Conn delegation
func (c *Conn) SetDeadline(t time.Time) error { //nolint:revive // net.Conn delegation
	return c.inner.SetDeadline(t)
}
func (c *Conn) SetReadDeadline(t time.Time) error { //nolint:revive // net.Conn delegation
	return c.inner.SetReadDeadline(t)
}
func (c *Conn) SetWriteDeadline(t time.Time) error { //nolint:revive // net.Conn delegation
	return c.inner.SetWriteDeadline(t)
}
