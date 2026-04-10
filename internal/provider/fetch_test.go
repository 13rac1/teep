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
		t.Logf("request: %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
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
	// Port 1 is reserved and will always refuse connections.
	_, err := provider.FetchAttestationJSON(context.Background(), http.DefaultClient, "http://127.0.0.1:1/attest", "key", 1<<20)
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	t.Logf("error: %v", err)
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
