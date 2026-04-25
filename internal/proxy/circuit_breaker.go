package proxy

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// defaultBreakerThreshold is the number of consecutive fetch failures that
	// opens the circuit for a provider.
	defaultBreakerThreshold = 5

	// defaultBreakerResetTimeout is how long the circuit stays open before
	// allowing a single probe request through.
	//
	// 60 seconds is intentionally longer than negativeCacheTTL (30 seconds).
	// The negative cache provides short-term backoff after individual failures.
	// The circuit breaker provides medium-term protection after repeated failures.
	// If both timeouts were equal, the negCache entry would expire and re-trigger
	// a new fetch attempt just as the circuit was probing, interleaving two
	// independent backoff mechanisms in a confusing way.
	defaultBreakerResetTimeout = 60 * time.Second
)

type cbState int

const (
	cbClosed   cbState = iota // normal; requests flow through
	cbOpen                    // failing fast; no upstream calls
	cbHalfOpen                // one probe allowed; waiting for outcome
)

func (s cbState) String() string {
	switch s {
	case cbClosed:
		return "closed"
	case cbOpen:
		return "open"
	case cbHalfOpen:
		return "half-open"
	default:
		return fmt.Sprintf("cbState(%d)", int(s))
	}
}

// circuitBreaker tracks consecutive attestation fetch failures for a single
// provider and opens the circuit after a configurable threshold. While open,
// allow() returns false immediately so no upstream HTTP call is made. After
// resetTimeout the circuit enters the half-open state and allows one probe
// request through. A successful probe closes the circuit; a failed probe
// reopens it.
//
// The breaker is keyed per-provider, not per-provider+model. A provider's
// attestation endpoint is shared across all its models; if it starts timing
// out it does so for every model, not selectively. Keying by (provider, model)
// would require threshold failures per model before any protection engaged,
// meaning tens of failures for a provider with many models before the first
// request was blocked.
//
// Caller contract: a caller that receives true from allow must call exactly
// one of success or failure when the upstream call completes. Failure to do so
// while the circuit is half-open will leave it permanently half-open.
type circuitBreaker struct {
	mu    sync.Mutex
	state cbState
	// failures counts fetch failures since the last success() call. It is only
	// incremented in cbClosed (counting toward the threshold) and cbHalfOpen
	// (counting probe failures). It is not incremented while cbOpen because the
	// circuit is already tripped and the count is irrelevant until it resets.
	failures     int
	openedAt     time.Time
	threshold    int
	resetTimeout time.Duration
	now          func() time.Time // injectable for tests; production uses time.Now
}

// allow reports whether the caller should proceed with an upstream fetch.
// It is safe for concurrent use.
func (cb *circuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbClosed:
		return true
	case cbOpen:
		if cb.now().Sub(cb.openedAt) >= cb.resetTimeout {
			cb.state = cbHalfOpen
			return true // allow the single probe
		}
		return false
	case cbHalfOpen:
		return false // probe already in flight
	default:
		panic("proxy: unhandled cbState in allow()")
	}
}

// success closes the circuit and resets the failure counter. Call after a
// successful upstream fetch.
func (cb *circuitBreaker) success() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state != cbClosed {
		slog.Warn("circuit breaker recovered",
			"previous_state", cb.state, "failures_cleared", cb.failures)
	}
	cb.state = cbClosed
	cb.failures = 0
}

// failure records a fetch failure. When the threshold is reached the circuit
// opens. A failure during the half-open probe reopens the circuit immediately.
// Failures while already open are discarded — the counter is only meaningful
// when counting toward the threshold or tracking probe outcomes.
func (cb *circuitBreaker) failure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbClosed:
		cb.failures++
		if cb.failures >= cb.threshold {
			slog.Warn("circuit breaker open",
				"failures", cb.failures, "threshold", cb.threshold)
			cb.state = cbOpen
			cb.openedAt = cb.now()
		}
	case cbHalfOpen:
		cb.failures++
		slog.Warn("circuit breaker reopened after probe failure",
			"failures", cb.failures)
		cb.state = cbOpen
		cb.openedAt = cb.now()
	case cbOpen:
		// Already open; discard. The counter is irrelevant until the circuit closes.
	default:
		panic("proxy: unhandled cbState in failure()")
	}
}
