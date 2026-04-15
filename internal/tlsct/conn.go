package tlsct

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
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
		if h == "" {
			return nil, fmt.Errorf("invalid host %q: empty host", host)
		}
		if p == "" {
			return nil, fmt.Errorf("invalid host %q: empty port", host)
		}
		// Reject bracketed non-IPv6 hosts like "[example.com]:443".
		if strings.ContainsAny(host, "[]") {
			if !strings.Contains(h, ":") || net.ParseIP(h) == nil {
				return nil, fmt.Errorf("invalid host %q: bracketed host must be an IPv6 literal", host)
			}
		}
		return DialAddr(ctx, h, net.JoinHostPort(h, p))
	}

	// Distinguish true bare hostnames from malformed host:port input.
	// Also accept bare IP addresses (including IPv6 literals). Only accept
	// bracketed input when it is a fully bracketed IPv6 literal like "[::1]".
	if host == "" {
		return nil, fmt.Errorf("invalid host %q: empty host", host)
	}
	if strings.HasSuffix(host, ":") {
		return nil, fmt.Errorf("invalid host %q: trailing colon", host)
	}

	hasLeadingBracket := strings.HasPrefix(host, "[")
	hasTrailingBracket := strings.HasSuffix(host, "]")
	if hasLeadingBracket || hasTrailingBracket {
		if !hasLeadingBracket || !hasTrailingBracket {
			return nil, fmt.Errorf("invalid host %q: unbalanced brackets", host)
		}

		bare := host[1 : len(host)-1]
		if bare == "" {
			return nil, fmt.Errorf("invalid host %q: empty host", host)
		}
		if strings.ContainsAny(bare, "[]") {
			return nil, fmt.Errorf("invalid host %q: malformed brackets", host)
		}
		if !strings.Contains(bare, ":") || net.ParseIP(bare) == nil {
			return nil, fmt.Errorf("invalid host %q: bracketed host must be an IPv6 literal", host)
		}

		return DialAddr(ctx, bare, net.JoinHostPort(bare, "443"))
	}

	if strings.ContainsAny(host, "[]") {
		return nil, fmt.Errorf("invalid host %q: malformed brackets", host)
	}

	isBareHostname := !strings.Contains(host, ":")
	isBareIP := net.ParseIP(host) != nil
	if isBareHostname || isBareIP {
		return DialAddr(ctx, host, net.JoinHostPort(host, "443"))
	}

	return nil, fmt.Errorf("invalid host %q: %w", host, err)
}

// DialAddr opens a TLS 1.3 connection to addr with the given serverName
// for SNI and certificate verification. The SPKI hash is extracted from
// the peer certificate after the handshake completes.
func DialAddr(ctx context.Context, serverName, addr string) (*Conn, error) {
	if serverName == "" {
		return nil, errors.New("invalid serverName: empty")
	}
	// Ensure ctx has a deadline so the full dial (TCP + TLS handshake)
	// is bounded even when the caller provides context.Background().
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultDialTimeout)
		defer cancel()
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{},
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
//
// Exported for use by provider test packages (nearcloud, neardirect) that
// create connections to httptest.TLSServer with custom root CAs. Cannot
// reside in export_test.go because callers span multiple packages.
func NewConn(tc *tls.Conn) (*Conn, error) {
	return newConn(tc)
}

func newConn(tc *tls.Conn) (*Conn, error) {
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		tc.Close()
		return nil, errors.New("no peer certificate from server")
	}
	leaf := state.PeerCertificates[0]
	h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	spki := hex.EncodeToString(h[:])
	return &Conn{inner: tc, spki: spki, tlsState: state}, nil
}

// SPKI returns the SHA-256 hex fingerprint of the peer certificate's
// SubjectPublicKeyInfo, computed at connection creation time.
func (c *Conn) SPKI() string { return c.spki }

// TLSState returns the TLS connection state captured at creation time.
// Callers use this with Checker.CheckTLSState for CT verification.
// Returns a shallow copy so callers cannot reassign top-level fields;
// referenced objects (e.g. PeerCertificates slice elements) are shared.
func (c *Conn) TLSState() *tls.ConnectionState {
	state := c.tlsState
	return &state
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
