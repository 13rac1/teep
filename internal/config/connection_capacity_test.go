package config

import (
	"errors"
	"net/http"
	"testing"

	"github.com/13rac1/teep/internal/tlsct"
)

func TestRetryTransportRejectsCapacityWithoutRetry(t *testing.T) {
	calls := 0
	rt := &RetryTransport{Base: rtFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, tlsct.ErrConnectionCapacity })}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, tlsct.ErrConnectionCapacity) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
