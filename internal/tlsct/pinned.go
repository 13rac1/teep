package tlsct

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrSPKIMismatch indicates that a TLS peer did not present the attested SPKI.
// It is returned during the TLS handshake, before any HTTP request bytes are
// written on the connection.
var ErrSPKIMismatch = errors.New("TLS peer SPKI does not match attested fingerprint")

// NewSPKIPinnedHTTPClientWithTransport returns an HTTP client that performs
// system-root WebPKI verification and then compares the live leaf SPKI with
// the attested fingerprint during every new TLS handshake. It rejects any
// caller-provided TLSClientConfig or TLS dialer, then installs the complete
// TLS configuration itself. Connections that pass may be safely reused
// because a TLS peer identity cannot change during an established connection.
//
// Certificate-transparency enforcement is composed into the same handshake
// through NewHTTPClientWithTransport. The caller must dedicate base to this
// pin; a transport pool must never contain connections authenticated under
// different expected fingerprints. TLS session resumption remains disabled.
func NewSPKIPinnedHTTPClientWithTransport(
	timeout time.Duration,
	base *http.Transport,
	expectedSPKI string,
	ctEnabled ...bool,
) (*http.Client, error) {
	expected, err := decodeSPKI(expectedSPKI)
	if err != nil {
		return nil, fmt.Errorf("invalid expected SPKI fingerprint: %w", err)
	}
	if base == nil {
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("http.DefaultTransport is not *http.Transport")
		}
		base = dt.Clone()
	}
	if err := validateSystemWebPKITransport(base); err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		ClientSessionCache: nil, // SPKI-scoped pools must perform full handshakes.
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("TLS peer did not provide a certificate")
		}
		actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
			return ErrSPKIMismatch
		}
		return nil
	}
	base.TLSClientConfig = tlsConfig

	return NewHTTPClientWithTransport(timeout, base, ctEnabled...), nil
}

func validateSystemWebPKITransport(base *http.Transport) error {
	if base.DialTLSContext != nil || base.DialTLS != nil { //nolint:staticcheck // deprecated hook must also be rejected
		return errors.New("SPKI-pinned transport must not set a custom TLS dialer")
	}
	if base.TLSClientConfig != nil {
		return errors.New("SPKI-pinned transport must not provide a custom TLSClientConfig")
	}
	return nil
}

// SPKIFingerprintsEqual compares two hex-encoded SHA-256 SPKI fingerprints in
// constant time. Malformed fingerprints never match.
func SPKIFingerprintsEqual(left, right string) bool {
	return CompareSPKIFingerprints(left, right) == nil
}

func decodeSPKI(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != sha256.Size {
		return nil, fmt.Errorf("decoded length %d, want %d", len(decoded), sha256.Size)
	}
	return decoded, nil
}
