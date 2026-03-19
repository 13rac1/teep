package attestation

import (
	"testing"
	"time"
)

// TestNewNonce verifies the nonce is 32 bytes and non-zero.
func TestNewNonce(t *testing.T) {
	n := NewNonce()

	allZero := true
	for _, b := range n {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("NewNonce returned all-zero nonce; crypto/rand may be broken")
	}

	hex := n.Hex()
	if len(hex) != 64 {
		t.Errorf("Nonce.Hex() length: got %d, want 64", len(hex))
	}
}

// TestNewNonceUniqueness verifies two nonces are statistically distinct.
func TestNewNonceUniqueness(t *testing.T) {
	a := NewNonce()
	b := NewNonce()
	if a == b {
		t.Error("two NewNonce calls returned the same value; crypto/rand may be broken")
	}
}

// TestParseNonce tests all ParseNonce paths.
func TestParseNonce(t *testing.T) {
	original := NewNonce()
	hex := original.Hex()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid 64-char hex",
			input:   hex,
			wantErr: false,
		},
		{
			name:    "all zeros",
			input:   "0000000000000000000000000000000000000000000000000000000000000000",
			wantErr: false,
		},
		{
			name:    "not hex",
			input:   "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
			wantErr: true,
		},
		{
			name:    "too short (62 chars)",
			input:   hex[:62],
			wantErr: true,
		},
		{
			name:    "too long (66 chars)",
			input:   hex + "ff",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseNonce(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseNonce(%q): expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseNonce(%q): unexpected error: %v", tc.input, err)
				return
			}
			// Round-trip: parsed nonce must hex-encode back to the same string.
			if got.Hex() != tc.input {
				t.Errorf("ParseNonce round-trip: got %q, want %q", got.Hex(), tc.input)
			}
		})
	}

	// Verify the original nonce survives a round-trip.
	parsed, err := ParseNonce(hex)
	if err != nil {
		t.Fatalf("round-trip ParseNonce: %v", err)
	}
	if parsed != original {
		t.Error("round-trip nonce mismatch")
	}
}

// TestCacheGetPutMiss tests the happy path and cache miss.
func TestCacheGetPutMiss(t *testing.T) {
	c := NewCache(time.Minute)
	report := &VerificationReport{Provider: "venice", Model: "test-model"}

	// Miss on empty cache.
	if _, ok := c.Get("venice", "test-model"); ok {
		t.Error("Get on empty cache returned ok=true")
	}

	c.Put("venice", "test-model", report)

	// Hit after put.
	got, ok := c.Get("venice", "test-model")
	if !ok {
		t.Fatal("Get after Put returned ok=false")
	}
	if got != report {
		t.Error("Get returned wrong report pointer")
	}

	// Different model key must miss.
	if _, ok := c.Get("venice", "other-model"); ok {
		t.Error("Get for different model returned ok=true")
	}

	// Different provider key must miss.
	if _, ok := c.Get("nearai", "test-model"); ok {
		t.Error("Get for different provider returned ok=true")
	}
}

// TestCacheTTLExpiry verifies expired entries are not returned.
func TestCacheTTLExpiry(t *testing.T) {
	c := NewCache(time.Millisecond) // 1ms TTL
	report := &VerificationReport{}
	c.Put("p", "m", report)

	// Immediately accessible.
	if _, ok := c.Get("p", "m"); !ok {
		t.Error("Get immediately after Put returned ok=false")
	}

	time.Sleep(5 * time.Millisecond) // let it expire

	if _, ok := c.Get("p", "m"); ok {
		t.Error("Get after TTL expiry returned ok=true")
	}
}

// TestNegativeCacheBasic tests the negative cache record and block flow.
func TestNegativeCacheBasic(t *testing.T) {
	c := NewNegativeCache(time.Minute)

	if c.IsBlocked("venice", "test-model") {
		t.Error("IsBlocked on empty cache returned true")
	}

	c.Record("venice", "test-model")

	if !c.IsBlocked("venice", "test-model") {
		t.Error("IsBlocked after Record returned false")
	}

	// Different key must not be blocked.
	if c.IsBlocked("venice", "other-model") {
		t.Error("IsBlocked for different model returned true")
	}
}

// TestNegativeCacheTTLExpiry verifies failure records expire.
func TestNegativeCacheTTLExpiry(t *testing.T) {
	c := NewNegativeCache(time.Millisecond)
	c.Record("p", "m")

	if !c.IsBlocked("p", "m") {
		t.Error("IsBlocked immediately after Record returned false")
	}

	time.Sleep(5 * time.Millisecond)

	if c.IsBlocked("p", "m") {
		t.Error("IsBlocked after TTL expiry returned true")
	}
}

// TestNegativeCacheOverwrite verifies that re-recording refreshes the timestamp.
func TestNegativeCacheOverwrite(t *testing.T) {
	c := NewNegativeCache(time.Millisecond)
	c.Record("p", "m")
	time.Sleep(5 * time.Millisecond) // let first entry expire

	// Record again — should reset the clock.
	c.Record("p", "m")
	if !c.IsBlocked("p", "m") {
		t.Error("IsBlocked after re-Record returned false")
	}
}
