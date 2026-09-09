package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestStandaloneTLSOnlyChatProbe(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, status := range []int{http.StatusOK, http.StatusInternalServerError, http.StatusMisdirectedRequest} {
			t.Run(http.StatusText(status), func(t *testing.T) {
				name := "neardirect"
				model, err := e2ee.NewNearCloudSession()
				if err != nil {
					t.Fatal(err)
				}
				defer model.Zero()
				if status == http.StatusMisdirectedRequest {
					name = "nearcloud"
				}
				calls := 0
				upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.URL.Path != "/v1/chat/completions" || r.ProtoMajor != 2 {
						t.Error("probe did not use streaming chat over HTTP/2")
					}
					for _, name := range []string{"X-Client-Pub-Key", "X-Encryption-Version", "X-Encrypt-All-Fields"} {
						if r.Header.Get(name) != "" {
							t.Error("TLS-only probe enabled encryption")
						}
					}
					if status == http.StatusMisdirectedRequest {
						if len(r.Header.Values("X-Model-Pub-Key")) != 1 {
							t.Error("missing routing key")
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(status)
						_, _ = fmt.Fprint(w, `{"error":{"type":"provider_error","message":"The encryption key is no longer valid. Please refresh your attestation report and retry.","param":null,"code":null}}`)
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					w.WriteHeader(status)
					_, _ = fmt.Fprint(w, "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n")
				}))
				route, err := provider.NewResolvedRoute(upstream.URL, "")
				if err != nil {
					t.Fatal(err)
				}
				fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
				identity, err := tlsct.NewTransportIdentity(route.Authority(), hex.EncodeToString(fp[:]))
				if err != nil {
					t.Fatal(err)
				}
				client, err := tlsct.NewSPKIPinnedHTTPClientWithTransport(0, tlsct.NewPooledTransport(), identity, true)
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseIdleConnections()
				probe, retry, err := testStandaloneInference(t.Context(), &Options{ProviderName: name, Provider: &config.Provider{BaseURL: upstream.URL, APIKey: "test", E2EE: false}, ModelName: "model"}, route, &attestation.RawAttestation{SigningKey: model.ClientEd25519PubHex()}, standaloneTestModelKey(t, model.ClientEd25519PubHex()), client)
				if retry || calls != 1 {
					t.Fatal("TLS-only probe replayed")
				}
				result := verificationOutcome{report: &attestation.VerificationReport{Factors: []attestation.FactorResult{{Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}}
				if probe != nil {
					result.e2ee = probe.e2ee
					result.tlsInference = probe.tlsInference
				}
				completeTLSOnlyInference(&result, err)
				if result.e2ee != nil || result.report.Factors[0].Status != attestation.Skip {
					t.Fatal("TLS-only result promoted E2EE")
				}
				if result.report.Blocked() != (status != http.StatusOK) {
					t.Fatalf("failed probe did not remain failed: %v", err)
				}
				if result.tlsInference == nil || !result.tlsInference.Attempted {
					t.Fatal("missing attempted TLS-only outcome")
				}
			})
		}
	})
}

func TestTLSOnlyProbeRejectsMissingChatText(t *testing.T) {
	for _, data := range []string{
		`{"object":"chat.completion.chunk"}`,
		`{"object":"chat.completion.chunk","choices":[{"delta":{"content":null,"Content":"extension only"}}]}`,
		`{"object":"chat.completion.chunk","choices":[{"delta":{"content":""},"Delta":{"content":"extension only"}}]}`,
		`{"object":"chat.completion.chunk","choices":[],"Choices":[{"delta":{"content":"extension only"}}]}`,
		`{"Object":"chat.completion.chunk","choices":[{"delta":{"content":"text"}}]}`,
		`{"object":"chat.completion.chunk","choices":[]}`,
		`{"object":"chat.completion.chunk","choices":[{"delta":{}}]}`,
		`{"object":"chat.completion.chunk","choices":"invalid"}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", data)
		}))
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		err = verifyTLSOnlyStream(resp)
		resp.Body.Close()
		server.Close()
		if err == nil {
			t.Fatal("TLS-only probe claimed success without valid chat text")
		}
	}
}

func TestTLSOnlyProbeValidatesEveryChunk(t *testing.T) {
	for _, tc := range []struct {
		name, chunk string
		valid       bool
	}{
		{"error_shadow", `{"object":"chat.completion.chunk","choices":[],"error":{"message":"failed"},"Error":null}`, false},
		{"choices_shadow", `{"object":"chat.completion.chunk","choices":null,"Choices":[]}`, false},
		{"delta_shadow", `{"object":"chat.completion.chunk","choices":[{"delta":null,"Delta":{}}]}`, false},
		{"content_shadow", `{"object":"chat.completion.chunk","choices":[{"delta":{"content":42,"Content":"text"}}]}`, false},
		{"object_shadow", `{"object":"invalid","Object":"chat.completion.chunk","choices":[]}`, false},
		{"null_choice", `{"object":"chat.completion.chunk","choices":[null]}`, false},
		{"missing_delta", `{"object":"chat.completion.chunk","choices":[{}]}`, false},
		{"null_delta", `{"object":"chat.completion.chunk","choices":[{"delta":null}]}`, false},
		{"missing_choices", `{"object":"chat.completion.chunk"}`, false},
		{"null_choices", `{"object":"chat.completion.chunk","choices":null}`, false},
		{"missing_object", `{"choices":[]}`, false},
		{"mixed_choices", `{"object":"chat.completion.chunk","choices":[{"delta":{"content":"text"}},null]}`, false},
		{"usage", `{"object":"chat.completion.chunk","choices":[],"usage":{"total_tokens":1}}`, true},
		{"null_content", `{"object":"chat.completion.chunk","choices":[{"delta":{"content":null,"role":"assistant"}}]}`, true},
		{"extensions", `{"object":"chat.completion.chunk","choices":[{"delta":{"content":"text","extension":true},"index":0}],"extension":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: %s\n\ndata: [DONE]\n\n", tc.chunk)
			}))
			defer server.Close()
			resp, err := server.Client().Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if err := verifyTLSOnlyStream(resp); (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func standaloneTestModelKey(t *testing.T, text string) e2ee.NearModelKey {
	t.Helper()
	key, err := e2ee.ParseNearModelKey(text)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
