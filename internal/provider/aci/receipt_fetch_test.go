package aci

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const liveReceiptID = "rcpt-5f0a8bd19ba732a726e95519"

// receiptServer serves the live receipt after notFound answers of HTTP 404,
// and counts the requests.
func receiptServer(t *testing.T, notFound int32, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	body, err := os.ReadFile("testdata/receipt_20261101.json")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != ReceiptsPath+"/"+liveReceiptID || r.Header.Get("Authorization") != "Bearer key" {
			t.Errorf("request %s %s, Authorization %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		switch {
		case n <= notFound:
			http.NotFound(w, r)
		case status != http.StatusOK:
			w.WriteHeader(status)
		default:
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestFetchReceipt(t *testing.T) {
	for _, tc := range []struct {
		name      string
		notFound  int32
		status    int
		wantErr   string
		wantCalls int32
	}{
		{"first attempt", 0, http.StatusOK, "", 1},
		{"after two 404 answers", 2, http.StatusOK, "", 3},
		{"404 on every attempt", 3, http.StatusOK, "HTTP 404 after 3 attempts", 3},
		{"other status ends the fetch", 0, http.StatusInternalServerError, "HTTP 500", 1},
		{"401 ends the fetch", 0, http.StatusUnauthorized, "HTTP 401", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := receiptServer(t, tc.notFound, tc.status)
			r, err := FetchReceipt(t.Context(), srv.Client(), srv.URL, "key", liveReceiptID)
			if tc.wantErr == "" && (err != nil || r == nil || r.ID != liveReceiptID) {
				t.Fatalf("FetchReceipt = %v, %v", r, err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			// Every HTTP answer that is not a receipt is the gateway's
			// statement (ErrReceiptNotServed).
			if tc.wantErr != "" && !errors.Is(err, ErrReceiptNotServed) {
				t.Errorf("err = %v, want ErrReceiptNotServed", err)
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Errorf("%d requests, want %d", got, tc.wantCalls)
			}
		})
	}
}

// The route of one id must serve the receipt of that id.
func TestFetchReceiptRefusesOtherReceipt(t *testing.T) {
	srv, _ := receiptServer(t, 0, http.StatusOK)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/receipt_20261101.json")
		_, _ = w.Write(body)
	})
	if _, err := FetchReceipt(t.Context(), srv.Client(), srv.URL, "key", "rcpt-other"); err == nil || !strings.Contains(err.Error(), "served receipt") {
		t.Fatalf("err = %v", err)
	}
}

// The caller's deadline ends the wait between attempts.
func TestFetchReceiptStopsAtDeadline(t *testing.T) {
	srv, calls := receiptServer(t, 3, http.StatusOK)
	ctx, cancel := context.WithTimeout(t.Context(), ReceiptRetryDelay/2)
	defer cancel()
	started := time.Now()
	if _, err := FetchReceipt(ctx, srv.Client(), srv.URL, "key", liveReceiptID); err == nil {
		t.Fatal("fetch succeeded after the deadline")
	}
	if calls.Load() != 1 || time.Since(started) >= ReceiptRetryDelay {
		t.Errorf("%d requests in %s, want 1 before the retry delay", calls.Load(), time.Since(started))
	}
}

// A transport failure and the end of the caller's context are not answers
// of the gateway, so they are not ErrReceiptNotServed.
func TestFetchReceiptTransportFailureIsNotAnAnswer(t *testing.T) {
	srv, _ := receiptServer(t, 0, http.StatusOK)
	srv.Config.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	_, err := FetchReceipt(t.Context(), srv.Client(), srv.URL, "key", liveReceiptID)
	if err == nil || errors.Is(err, ErrReceiptNotServed) || errors.Is(err, ErrMalformedReceipt) {
		t.Fatalf("aborted fetch: err = %v, want a transport error", err)
	}
	slow, _ := receiptServer(t, 3, http.StatusOK)
	ctx, cancel := context.WithTimeout(t.Context(), ReceiptRetryDelay/2)
	defer cancel()
	if _, err := FetchReceipt(ctx, slow.Client(), slow.URL, "key", liveReceiptID); err == nil || errors.Is(err, ErrReceiptNotServed) {
		t.Fatalf("fetch at the deadline: err = %v, want the context error", err)
	}
}

func TestFetchReceiptNeedsAPIKey(t *testing.T) {
	srv, calls := receiptServer(t, 0, http.StatusOK)
	if _, err := FetchReceipt(t.Context(), srv.Client(), srv.URL, "", liveReceiptID); err == nil || calls.Load() != 0 {
		t.Fatalf("err = %v, %d requests", err, calls.Load())
	}
}

func TestReceiptID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		ok     bool
	}{
		{"live form", []string{liveReceiptID}, true},
		{"absent", nil, false},
		{"two values", []string{"a", "b"}, false},
		{"empty", []string{""}, false},
		{"path separator", []string{"rcpt/../x"}, false},
		{"query", []string{"rcpt?x=1"}, false},
		{"too long", []string{strings.Repeat("a", 129)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tc.values {
				h.Add("X-Receipt-Id", v)
			}
			id, err := ReceiptID(h)
			if (err == nil) != tc.ok || (tc.ok && id != tc.values[0]) {
				t.Fatalf("ReceiptID = %q, %v", id, err)
			}
		})
	}
}
