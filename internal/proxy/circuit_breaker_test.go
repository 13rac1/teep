package proxy

import (
	"testing"
	"time"
)

// newTestBreaker creates a circuit breaker with controllable time. The returned
// *time.Time pointer can be reassigned to advance the clock seen by the breaker.
func newTestBreaker(threshold int) (*circuitBreaker, *time.Time) {
	now := time.Now()
	cb := &circuitBreaker{
		threshold:    threshold,
		resetTimeout: time.Minute,
		now:          func() time.Time { return now },
	}
	return cb, &now
}

func TestCircuitBreaker_InitialState(t *testing.T) {
	cb, _ := newTestBreaker(3)
	for range 5 {
		if !cb.allow() {
			t.Error("new circuit breaker should allow all requests")
		}
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb, _ := newTestBreaker(3)

	for i := range 2 {
		cb.failure()
		if !cb.allow() {
			t.Errorf("circuit should still be closed after %d failure(s)", i+1)
		}
	}

	cb.failure() // 3rd — hits threshold
	if cb.allow() {
		t.Error("circuit should be open after threshold failures")
	}
}

func TestCircuitBreaker_OpenBlocksRequests(t *testing.T) {
	cb, _ := newTestBreaker(1)
	cb.failure() // open immediately (threshold = 1)

	for range 5 {
		if cb.allow() {
			t.Error("open circuit should block all requests")
		}
	}
}

func TestCircuitBreaker_HalfOpenAfterReset(t *testing.T) {
	cb, nowPtr := newTestBreaker(1)
	cb.failure() // open

	if cb.allow() {
		t.Error("circuit should be blocked immediately after opening")
	}

	*nowPtr = nowPtr.Add(time.Minute + time.Second) // advance past resetTimeout

	if !cb.allow() {
		t.Error("circuit should allow probe after reset timeout")
	}
	// Already half-open; second call should block (probe in flight).
	if cb.allow() {
		t.Error("only one probe should be allowed while half-open")
	}
}

func TestCircuitBreaker_RecoveryClosesCircuit(t *testing.T) {
	cb, nowPtr := newTestBreaker(1)
	cb.failure()                                    // open
	*nowPtr = nowPtr.Add(time.Minute + time.Second) // advance past reset
	cb.allow()                                      // transitions to half-open
	cb.success()                                    // probe succeeded → closed

	if !cb.allow() {
		t.Error("circuit should be closed after successful probe")
	}
}

func TestCircuitBreaker_ProbeFailureReopens(t *testing.T) {
	cb, nowPtr := newTestBreaker(1)
	cb.failure()                                    // open
	*nowPtr = nowPtr.Add(time.Minute + time.Second) // advance past reset
	cb.allow()                                      // transitions to half-open
	cb.failure()                                    // probe failed → reopen

	if cb.allow() {
		t.Error("circuit should be open after probe failure")
	}
}

func TestBreakerFor(t *testing.T) {
	s := &Server{}
	b1 := s.breakerFor("provider-a")
	b2 := s.breakerFor("provider-a")
	b3 := s.breakerFor("provider-b")

	if b1 != b2 {
		t.Error("breakerFor should return the same *circuitBreaker for the same provider name")
	}
	if b1 == b3 {
		t.Error("breakerFor should return different *circuitBreakers for different provider names")
	}
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	cb, _ := newTestBreaker(3)

	for range 2 {
		cb.failure()
	}
	cb.success() // reset

	// Need a full threshold of new failures to open again.
	for i := range 2 {
		cb.failure()
		if !cb.allow() {
			t.Errorf("circuit should still be closed after %d failure(s) post-reset", i+1)
		}
	}
	cb.failure() // 3rd — threshold
	if cb.allow() {
		t.Error("circuit should open after new threshold failures post-reset")
	}
}
