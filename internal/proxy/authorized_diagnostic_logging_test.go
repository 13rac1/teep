package proxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func captureInferenceDiagnostics(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestAuthorizedRetryLogsFailedAttempt(t *testing.T) {
	key, value := testAuthorizationCandidate(t, "model")
	value.generation = 7
	value.publishedAt = time.Now()
	trace := &tlsct.InferenceAttempt{}
	ctx := trace.Context(t.Context())
	httptrace.ContextClientTrace(ctx).GetConn(key.Authority())
	input := &authorizedRequest{provider: &provider.Provider{Name: key.ProviderName()}, key: key, body: []byte("private request data")}
	result := authorizedResponse{retryReason: "connection_establishment", outcome: authorizedOutcome{trace: trace, diagnostics: authorizationIdentityDiagnostics(value)}}
	logs := captureInferenceDiagnostics(t)
	logAuthorizedRetry(ctx, input, &result, 1, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")})
	for _, field := range []string{"level=WARN", "authorized inference retry scheduled", "inference_attempt=1", "retry_reason=connection_establishment", "connection refused", "failure_phase=connection_acquire", "connection_acquire=", "connection_assigned=false", "authorization_generation=7", "authority=" + value.identity.Authority()} {
		if !strings.Contains(logs.String(), field) {
			t.Fatalf("missing %q: %s", field, logs.String())
		}
	}
	if strings.Contains(logs.String(), string(input.body)) {
		t.Fatal("retry logged request data")
	}
}

func TestAuthorizedAcquisitionFailureLogsPhase(t *testing.T) {
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	defer server.Close()
	server.authorizations.close()
	route, err := provider.NewResolvedRoute("https://model.example", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey("neardirect", "model")
	if err != nil {
		t.Fatal(err)
	}
	logs := captureInferenceDiagnostics(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	out := server.handleAuthorizedEndpoint(ctx, newInferenceRecorder(), &authorizedRequest{provider: &provider.Provider{Name: "neardirect"}, route: route, key: key})
	if out.status != "authorization_failed" {
		t.Fatalf("status=%s", out.status)
	}
	for _, field := range []string{"level=WARN", "authorized inference failed", "failure_phase=authorization", "authority=model.example", "inference_timeout_budget="} {
		if !strings.Contains(logs.String(), field) {
			t.Fatalf("missing %q: %s", field, logs.String())
		}
	}
	if strings.Contains(logs.String(), "authorization_generation=") {
		t.Fatal("unacquired authorization reported a generation")
	}
	for i := 0; i < len(out.summary); i += 2 {
		if out.summary[i] == "inference_timeout_budget" {
			budget := out.summary[i+1].(time.Duration)
			if budget <= 0 || budget > 10*time.Second {
				t.Fatalf("timeout budget does not reflect caller deadline: %v", budget)
			}
		}
	}
	if !strings.Contains(fmt.Sprint(out.summary), "failure_phase authorization") {
		t.Fatal("completion summary lacks authorization phase")
	}
}

func TestAuthorizedFailureLogsUsedIdentity(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("canceled=%t", canceled), func(t *testing.T) {
				private := authorizedTestKey(t)
				upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
					if err != nil {
						t.Error(err)
						return
					}
					_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
					body, nonce := encryptAuthorizedTestResponse(t, private, encap, [][]byte{[]byte(`{"choices":[]}`)})
					w.Header().Set("Ehbp-Response-Nonce", nonce)
					if !canceled {
						w.WriteHeader(http.StatusServiceUnavailable)
					}
					_, _ = w.Write(body)
				}))
				defer upstream.Close()
				server, input, value := authorizedFailureFixture(t, upstream, private)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var writer http.ResponseWriter = newInferenceRecorder()
				if canceled {
					writer = cancelResponseWriter{newInferenceRecorder(), cancel}
				}
				logs := captureInferenceDiagnostics(t)
				out := server.handleAuthorizedEndpoint(ctx, writer, input)
				if canceled {
					if out.status != "canceled" || strings.Contains(logs.String(), "authorized inference failed") {
						t.Fatalf("caller cancellation warning or status: %s %s", out.status, logs.String())
					}
					fields := make(map[string]any)
					for i := 0; i < len(out.summary); i += 2 {
						fields[out.summary[i].(string)] = out.summary[i+1]
					}
					if fields["authority"] != value.identity.Authority() || fields["authorization_generation"] != value.generation || fields["authorization_published_at"] != value.publishedAt {
						t.Fatalf("missing identity in completion: %v", fields)
					}
					return
				}
				for _, field := range []string{"level=WARN", "authorized inference failed", "authority=" + value.identity.Authority(), fmt.Sprintf("authorization_generation=%d", value.generation), "authorization_published_at=", "failure_phase=response_body", "upstream returned HTTP 503", "upstream_status_code=503"} {
					if !strings.Contains(logs.String(), field) {
						t.Fatalf("missing %q: %s", field, logs.String())
					}
				}
				if strings.Contains(logs.String(), "authorization_removed=") {
					t.Fatal("ordinary failure claimed authorization invalidation")
				}
			})
		}
	})
}
