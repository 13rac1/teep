package provider_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider"
)

func TestFetchAttestationJSON_OK(t *testing.T) {
	want := []byte(`{"attestation":"data","nonce":"abc123"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("request: %s %s", r.Method, r.URL.Path)
		if r.Method != http.MethodGet {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	got, err := provider.FetchAttestationJSON(context.Background(), srv.Client(), srv.URL+"/attest", "test-key", 1<<20)
	if err != nil {
		t.Fatalf("FetchAttestationJSON: %v", err)
	}
	t.Logf("response: %s", got)
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFetchAttestationJSON_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden: not in whitelist"))
	}))
	defer srv.Close()

	_, err := provider.FetchAttestationJSON(context.Background(), srv.Client(), srv.URL+"/attest", "key", 1<<20)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error should mention HTTP 403: %v", err)
	}
}

func TestFetchAttestationJSON_NetworkError(t *testing.T) {
	// Start then immediately close a server so the port is guaranteed to
	// refuse connections (no port-in-use race, no system policy variation).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL
	ts.Close()

	_, err := provider.FetchAttestationJSON(context.Background(), ts.Client(), url+"/attest", "key", 1<<20)
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	t.Logf("error: %v", err)
}

func TestFetchAttestationWithTLS_PlainHTTP(t *testing.T) {
	// Plain HTTP test server — peerSPKIHex should be empty.
	want := []byte(`{"attestation":"data"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	body, spki, err := provider.FetchAttestationWithTLS(context.Background(), srv.Client(), srv.URL+"/attest", "key", 1<<20)
	if err != nil {
		t.Fatalf("FetchAttestationWithTLS: %v", err)
	}
	if !bytes.Equal(body, want) {
		t.Errorf("body = %q, want %q", body, want)
	}
	if spki != "" {
		t.Errorf("expected empty peerSPKIHex for plain HTTP, got %q", spki)
	}
}

func TestFetchAttestationWithTLS_TLSServer(t *testing.T) {
	// TLS test server — peerSPKIHex should be non-empty hex.
	want := []byte(`{"attestation":"data"}`)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	body, spki, err := provider.FetchAttestationWithTLS(context.Background(), srv.Client(), srv.URL+"/attest", "key", 1<<20)
	if err != nil {
		t.Fatalf("FetchAttestationWithTLS: %v", err)
	}
	if !bytes.Equal(body, want) {
		t.Errorf("body = %q, want %q", body, want)
	}
	if spki == "" {
		t.Fatal("expected non-empty peerSPKIHex for TLS server")
	}
	if len(spki) != 64 {
		t.Errorf("peerSPKIHex length = %d, want 64 (SHA-256 hex)", len(spki))
	}
}

func TestFetchAttestationWithTLS_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	_, _, err := provider.FetchAttestationWithTLS(context.Background(), srv.Client(), srv.URL+"/attest", "key", 1<<20)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error should mention HTTP 403: %v", err)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"ab", 0, "..."},
		{"abc", 1, "a..."},
	}
	for _, tt := range tests {
		got := provider.Truncate(tt.input, tt.n)
		t.Logf("Truncate(%q, %d) = %q", tt.input, tt.n, got)
		if got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}
