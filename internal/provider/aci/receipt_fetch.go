package aci

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
)

// The receipt GET sends at most ReceiptAttempts requests, ReceiptRetryDelay
// apart. The gateway can store a receipt after the response ends, so only
// HTTP 404 gets another attempt; every other failure ends the fetch.
const (
	ReceiptAttempts   = 3
	ReceiptRetryDelay = 200 * time.Millisecond
)

// ErrMalformedReceipt marks a receipt that the gateway served but that is
// not a receipt of the requested id.
var ErrMalformedReceipt = errors.New("malformed receipt")

// maxReceiptIDLen bounds an X-Receipt-Id value (29 characters on
// 2026-11-01).
const maxReceiptIDLen = 128

// ReceiptID returns the one X-Receipt-Id value of a response (ACI/1 §7.1).
// The value must be 1 to 128 characters of [A-Za-z0-9_-], so that it is
// one path segment of the receipt route.
func ReceiptID(h http.Header) (string, error) {
	values := h.Values("X-Receipt-Id")
	if len(values) != 1 {
		return "", fmt.Errorf("response has %d X-Receipt-Id values, want 1", len(values))
	}
	id := values[0]
	if id == "" || len(id) > maxReceiptIDLen || strings.IndexFunc(id, notReceiptIDChar) >= 0 {
		return "", errors.New("response X-Receipt-Id is not 1 to 128 characters of [A-Za-z0-9_-]")
	}
	return id, nil
}

func notReceiptIDChar(r rune) bool {
	return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
}

// FetchReceipt gets and parses the receipt id from baseURL with the API key
// of the request that the receipt covers. The caller supplies client, which
// must be the client pinned to the attested TLS key of the gateway. The
// caller's ctx bounds every attempt and every wait.
func FetchReceipt(ctx context.Context, client *http.Client, baseURL, apiKey, id string) (*Receipt, error) {
	if apiKey == "" {
		return nil, errors.New("receipt fetch needs the API key of the request")
	}
	for attempt := 1; ; attempt++ {
		body, status, err := getReceipt(ctx, client, baseURL+ReceiptsPath+"/"+id, apiKey)
		switch {
		case err != nil:
			return nil, fmt.Errorf("receipt %s: %w", id, err)
		case status == http.StatusOK:
			r, err := ParseReceipt(body)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrMalformedReceipt, err)
			}
			if r.ID != id {
				return nil, fmt.Errorf("%w: receipt route %s served receipt %s", ErrMalformedReceipt, id, r.ID)
			}
			return r, nil
		case status != http.StatusNotFound:
			return nil, fmt.Errorf("receipt %s: HTTP %d", id, status)
		case attempt == ReceiptAttempts:
			return nil, fmt.Errorf("receipt %s: HTTP 404 after %d attempts %s apart", id, ReceiptAttempts, ReceiptRetryDelay)
		}
		timer := time.NewTimer(ReceiptRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("receipt %s: %w", id, ctx.Err())
		case <-timer.C:
		}
	}
}

func getReceipt(ctx context.Context, client *http.Client, url, apiKey string) (body []byte, status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	tlsct.SetUserAgent(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, MaxReceiptBytes+1))
	if err != nil {
		return nil, 0, err
	}
	return body, http.StatusOK, nil
}
