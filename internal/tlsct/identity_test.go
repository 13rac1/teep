package tlsct

import (
	"errors"
	"strings"
	"testing"
)

func TestHTTPSOriginAuthority(t *testing.T) {
	for origin, want := range map[string]string{
		"https://EXAMPLE.com.:443":   "example.com",
		"https://example.com:0444":   "example.com:444",
		"https://[2001:0db8::1]:443": "[2001:db8::1]",
		"https://127.0.0.1:444":      "127.0.0.1:444",
	} {
		got, err := HTTPSOriginAuthority(origin)
		if err != nil || got != want {
			t.Errorf("HTTPSOriginAuthority(%q) = %q, %v; want %q", origin, got, err, want)
		}
	}
	for _, origin := range []string{
		"", "http://example.com", "https://", "https://user@example.com",
		"https://example.com/", "https://example.com/path", "https://example.com?",
		"https://example.com#", "https://example.com:0", "https://example.com:65536",
		"https://example.com:", "https://[fe80::1%25eth0]", "https://%65xample.com",
		"https://éxample.com", "https://-example.com", "https://example..com",
		"https:example.com", "https://example.com/a%2fb",
	} {
		if _, err := HTTPSOriginAuthority(origin); err == nil {
			t.Errorf("accepted invalid origin %q", origin)
		}
	}
}

func TestTransportIdentity(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	i, err := NewTransportIdentity("example.com", fp)
	if err != nil {
		t.Fatal(err)
	}
	upper, err := NewTransportIdentity("example.com", strings.ToUpper(fp))
	if err != nil {
		t.Fatal(err)
	}
	if !i.Equal(upper) || i.Authority() != "example.com" || CompareSPKIFingerprints(i.Fingerprint(), fp) != nil {
		t.Fatal("identity did not retain its canonical authority and decoded fingerprint")
	}
	for _, authority := range []string{"", "EXAMPLE.com", "example.com:443", "example.com/"} {
		if _, err := NewTransportIdentity(authority, fp); err == nil {
			t.Errorf("accepted %q", authority)
		}
	}
	for _, fp := range []string{"", "ab", strings.Repeat("x", 64), strings.Repeat("ab", 33)} {
		if _, err := NewTransportIdentity("example.com", fp); err == nil {
			t.Error("accepted malformed fingerprint")
		}
	}
	if !errors.Is(CompareSPKIFingerprints(fp, strings.Repeat("cd", 32)), ErrSPKIMismatch) {
		t.Fatal("valid mismatch must return ErrSPKIMismatch")
	}
	if err := CompareSPKIFingerprints(fp, "bad"); err == nil || errors.Is(err, ErrSPKIMismatch) {
		t.Fatal("malformed fingerprint must be distinguished from a valid mismatch")
	}
}
