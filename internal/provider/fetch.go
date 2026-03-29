package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("read attestation response body: %w", err)
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
