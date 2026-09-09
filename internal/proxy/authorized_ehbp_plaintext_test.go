package proxy

import (
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedEHBPPlaintextStatus(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, status := range []int{200, 201, 204, 206, 400, 403, 404, 422, 429, 500, 503} {
			t.Run(strconv.Itoa(status), func(t *testing.T) {
				private := authorizedTestKey(t)
				diagnostic := `{"type":"urn:example:error:service"}`
				if status == http.StatusServiceUnavailable {
					diagnostic += strings.Repeat(" ", 10<<20)
				}
				var requests atomic.Int32
				upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
					if err != nil {
						t.Error(err)
						return
					}
					_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(status)
					if status != http.StatusNoContent {
						_, _ = io.WriteString(w, diagnostic)
					}
				}))
				defer upstream.Close()
				server, input, value := authorizedFailureFixture(t, upstream, private)
				recorder := newInferenceRecorder()
				outcome := server.handleAuthorizedEndpoint(t.Context(), recorder, input)
				success := status >= http.StatusOK && status < http.StatusMultipleChoices
				expectedStatus := status
				expectedBody := diagnostic[:min(len(diagnostic), 10<<20)]
				if success {
					expectedStatus = http.StatusBadGateway
				}
				if recorder.Code != expectedStatus {
					t.Fatalf("status=%d, want %d", recorder.Code, expectedStatus)
				}
				if !success && recorder.Body.String() != expectedBody {
					t.Fatal("plaintext error body was not preserved within its bound")
				}
				current, retained := server.authorizations.acquire(input.key)
				if retained == success {
					t.Fatalf("authorization retained=%v", retained)
				}
				if retained && current.generation != value.generation {
					t.Fatal("diagnostic changed authorization generation")
				}
				if requests.Load() != 1 || outcome.status == "ok" {
					t.Fatal("plaintext response retried or counted as successful")
				}
				if !success {
					if server.negCache.IsBlocked(input.key.ProviderName(), input.key.EvidenceScope().SingleflightKey()) {
						t.Fatal("diagnostic started a cooldown")
					}
					for _, factor := range current.report.Factors {
						if factor.Name == attestation.FactorE2EEUsable && factor.Status == attestation.Pass {
							t.Fatal("diagnostic promoted E2EE success")
						}
					}
				}
			})
		}
	})
}
