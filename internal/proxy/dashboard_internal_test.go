package proxy

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

func TestHitRateString(t *testing.T) {
	tests := []struct {
		hits, misses int64
		want         string
	}{
		{0, 0, "—"},
		{1, 0, "100%"},
		{0, 1, "0%"},
		{1, 1, "50%"},
		{3, 1, "75%"},
		{1, 3, "25%"},
		{99, 1, "99%"},
		{1000, 0, "100%"},
	}
	for _, tt := range tests {
		got := hitRateString(tt.hits, tt.misses)
		t.Logf("hitRateString(%d, %d) = %q", tt.hits, tt.misses, got)
		if got != tt.want {
			t.Errorf("hitRateString(%d, %d) = %q, want %q", tt.hits, tt.misses, got, tt.want)
		}
	}
}

func TestBuildHTTPStats(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(0),
		negCache: attestation.NewNegativeCache(0),
		stats:    stats{models: make(map[string]*modelStats)},
	}

	// Zero state.
	h := s.buildHTTPStats()
	t.Logf("zero state: requests=%d errors=%d", h.Requests, h.Errors)
	if h.Requests != 0 {
		t.Errorf("zero state requests = %d, want 0", h.Requests)
	}
	if h.Errors != 0 {
		t.Errorf("zero state errors = %d, want 0", h.Errors)
	}

	// Populate counters.
	s.stats.httpRequests.Store(10)
	s.stats.httpErrors.Store(2)

	h = s.buildHTTPStats()
	t.Logf("populated: requests=%d errors=%d", h.Requests, h.Errors)
	if h.Requests != 10 {
		t.Errorf("requests = %d, want 10", h.Requests)
	}
	if h.Errors != 2 {
		t.Errorf("errors = %d, want 2", h.Errors)
	}
}
