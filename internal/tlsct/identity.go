package tlsct

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// TransportIdentity identifies one attested HTTPS authority and SPKI.
// Its fields are private so callers cannot change a validated identity.
type TransportIdentity struct {
	authority   string
	fingerprint [sha256.Size]byte
}

// NewTransportIdentity requires a canonical authority and a SHA-256 SPKI.
func NewTransportIdentity(authority, fingerprint string) (TransportIdentity, error) {
	canonical, err := HTTPSOriginAuthority("https://" + authority)
	if err != nil || canonical != authority {
		return TransportIdentity{}, errors.New("transport authority is missing, invalid, or not canonical")
	}
	decoded, err := decodeSPKI(fingerprint)
	if err != nil {
		return TransportIdentity{}, fmt.Errorf("transport fingerprint: %w", err)
	}
	identity := TransportIdentity{authority: canonical}
	copy(identity.fingerprint[:], decoded)
	return identity, nil
}

// Authority returns the canonical HTTPS authority.
func (i TransportIdentity) Authority() string { return i.authority }

// Fingerprint returns the hexadecimal SHA-256 SPKI fingerprint.
func (i TransportIdentity) Fingerprint() string { return hex.EncodeToString(i.fingerprint[:]) }

// Equal compares authority and SPKI, with constant-time SPKI comparison.
func (i TransportIdentity) Equal(other TransportIdentity) bool {
	return i.authority == other.authority && subtle.ConstantTimeCompare(i.fingerprint[:], other.fingerprint[:]) == 1
}

// HTTPSOriginAuthority validates an origin-only HTTPS URL and normalizes its
// authority. Paths, userinfo, query strings, fragments, and zones are rejected.
func HTTPSOriginAuthority(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return "", errors.New("invalid HTTPS origin")
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || u.Opaque != "" || strings.ContainsAny(origin, "%#") {
		return "", errors.New("expected origin-only absolute HTTPS URL")
	}
	if strings.HasPrefix(u.Host, "[") {
		address, err := netip.ParseAddr(u.Hostname())
		if err != nil || !address.Is6() {
			return "", errors.New("bracketed authority must contain an IPv6 address")
		}
	}
	host, err := canonicalOriginHost(u.Hostname())
	if err != nil {
		return "", err
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("empty HTTPS port")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid HTTPS port")
		}
		if n != 443 {
			return net.JoinHostPort(host, strconv.Itoa(n)), nil
		}
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]", nil
	}
	return host, nil
}

func canonicalOriginHost(host string) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", errors.New("IPv6 zones are not allowed")
		}
		return addr.String(), nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(host) > 253 {
		return "", errors.New("invalid DNS hostname length")
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errors.New("invalid DNS hostname character")
			}
		}
	}
	return host, nil
}

// CompareSPKIFingerprints distinguishes malformed fingerprints from a mismatch.
func CompareSPKIFingerprints(left, right string) error {
	l, err := decodeSPKI(left)
	if err != nil {
		return fmt.Errorf("first SPKI fingerprint: %w", err)
	}
	r, err := decodeSPKI(right)
	if err != nil {
		return fmt.Errorf("second SPKI fingerprint: %w", err)
	}
	if subtle.ConstantTimeCompare(l, r) != 1 {
		return ErrSPKIMismatch
	}
	return nil
}
