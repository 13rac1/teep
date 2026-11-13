package attestation

import (
	"testing"
	"time"
)

// The attestation cache ends an ACI/1 report at its keyset not_after even
// within the TTL, and counts an ACI/1 report without a valid not_after as
// expired. A report of another format, with no keyset, behaves as before.
func TestCacheEndsACIReportAtKeysetNotAfter(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name   string
		report *VerificationReport
		hit    bool
	}{
		{"no keyset (dstack)", &VerificationReport{BackendFormat: FormatDstack}, true},
		{"no keyset, no format", &VerificationReport{}, true},
		{"ACI/1 before not_after", &VerificationReport{BackendFormat: FormatACI1, ACIKeysetNotAfter: now.Add(time.Minute).Unix()}, true},
		{"ACI/1 at not_after", &VerificationReport{BackendFormat: FormatACI1, ACIKeysetNotAfter: now.Unix()}, false},
		{"ACI/1 after not_after", &VerificationReport{BackendFormat: FormatACI1, ACIKeysetNotAfter: now.Add(-time.Minute).Unix()}, false},
		{"ACI/1 without not_after", &VerificationReport{BackendFormat: FormatACI1}, false},
		{"ACI/1 with a negative not_after", &VerificationReport{BackendFormat: FormatACI1, ACIKeysetNotAfter: -1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(time.Hour)
			c.Put("venice", "m", tc.report)
			if _, ok := c.Get("venice", "m"); ok != tc.hit {
				t.Fatalf("Get hit = %v, want %v", ok, tc.hit)
			}
		})
	}
}

// GetPublication uses the cache clock: a report is a hit one second before
// its keyset not_after and a miss at not_after, within the TTL.
func TestCacheKeysetNotAfterAtChosenTime(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	c := NewCache(time.Hour)
	c.now = func() time.Time { return at }
	c.Put("venice", "m", &VerificationReport{BackendFormat: FormatACI1, ACIKeysetNotAfter: at.Unix() + 60})
	at = at.Add(59 * time.Second)
	if _, ok := c.Get("venice", "m"); !ok {
		t.Fatal("miss one second before not_after")
	}
	at = at.Add(time.Second)
	if _, ok := c.Get("venice", "m"); ok {
		t.Fatal("hit at not_after")
	}
}

// ACIKeysetExpired is the one rule for every cache: before not_after the
// keyset is usable, from not_after on it is not.
func TestACIKeysetExpiredBoundary(t *testing.T) {
	r := &VerificationReport{BackendFormat: FormatACI1, ACIKeysetNotAfter: 1_800_000_000}
	if r.ACIKeysetExpired(time.Unix(1_800_000_000-1, 0)) {
		t.Error("expired one second before not_after")
	}
	if !r.ACIKeysetExpired(time.Unix(1_800_000_000, 0)) {
		t.Error("usable at not_after")
	}
	var none *VerificationReport
	if none.ACIKeysetExpired(time.Now()) {
		t.Error("a nil report is expired")
	}
}

// BuildReport carries the keyset not_after of every ACI/1 report, not only
// the canonical one.
func TestBuildReportCarriesACIKeysetNotAfter(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.BackendFormat = FormatACI1
	raw.ACIKeysetNotAfter = 1_800_000_000
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, AllowFail: ACIDefaultAllowFail})
	if report.ACIKeysetNotAfter != 1_800_000_000 {
		t.Fatalf("ACIKeysetNotAfter = %d", report.ACIKeysetNotAfter)
	}
}
