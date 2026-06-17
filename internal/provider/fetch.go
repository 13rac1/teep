package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// UserAgent is the User-Agent header sent on outbound requests to external
// APIs (GitHub, etc.). GitHub requires a User-Agent and will return
// 403/blocked responses without one, which previously caused confusing
// rate-limit-style failures.
// Ref: https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2026-03-10#user-agent
const UserAgent = "teep/1.0 (+https://github.com/13rac1/teep)"

// SetUserAgent sets the User-Agent header on req to UserAgent. Centralized so
// every outbound HTTP fetch to external services is consistent.
func SetUserAgent(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
}

// FetchAttestationJSON performs a GET to url with a Bearer token, reads up to
// limit bytes, and returns the response body. Returns an error with the
// truncated body for non-200 responses.
func FetchAttestationJSON(ctx context.Context, client *http.Client, url, apiKey string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build attestation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		// Host+Path only — never include query parameters (may contain nonce).
		return nil, fmt.Errorf("GET %s%s: %w", req.URL.Host, req.URL.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read attestation response body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("attestation response body exceeds size limit %d", limit)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation endpoint returned HTTP %d: %s", resp.StatusCode, Truncate(string(body), 512))
	}

	return body, nil
}

// Truncate returns s truncated to n characters with "..." appended if needed.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
