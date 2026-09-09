package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/golang-jwt/jwt/v5"
)

// Verify a real signed NRAS response; only its retrieval is supplied by the test.
func testNRASAdmission(t *testing.T, now time.Time) attestation.AdmissionTime {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES384, jwt.MapClaims{
		"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix(),
		"x-nvidia-overall-att-result": true,
	})
	token.Header["kid"] = "test"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := func(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
	jwks := fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-384","kid":"test","use":"sig","alg":"ES384","x":%q,"y":%q}]}`, coordinate(key.X.FillBytes(make([]byte, 48))), coordinate(key.Y.FillBytes(make([]byte, 48))))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			_, _ = fmt.Fprint(w, jwks)
			return
		}
		_, _ = fmt.Fprintf(w, `[["JWT","%s"],{}]`, signed)
	}))
	defer srv.Close()
	verifier := attestation.NewNVIDIAVerifier(srv.URL, srv.URL+"/jwks")
	defer verifier.Shutdown()
	result := verifier.VerifyNRAS(t.Context(), `{}`, srv.Client(), jwt.WithTimeFunc(func() time.Time { return now }))
	if result.SignatureErr != nil || result.ClaimsErr != nil {
		t.Fatalf("NRAS verification: signature=%v claims=%v", result.SignatureErr, result.ClaimsErr)
	}
	admission := attestation.NVIDIAAdmission(result)
	if err := admission.Check(now.Add(2 * time.Hour)); err == nil {
		t.Fatal("fixture did not supply authenticated admission time")
	}
	return admission
}

func TestAuthorizationNRASAdmissionAndReuse(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	admission := testNRASAdmission(t, now)
	for _, delayed := range []bool{false, true} {
		t.Run(fmt.Sprintf("delayed=%v", delayed), func(t *testing.T) {
			store := newAuthorizationStore(2, 1, time.Second)
			defer store.close()
			at := now
			store.now = func() time.Time { return at }
			key, candidate := testAuthorizationCandidate(t, "model")
			value, _, err := store.load(t.Context(), key, nil, nil, func(context.Context) (authorizationVerification, error) {
				if delayed {
					at = now.Add(time.Hour + 10*time.Second)
				}
				return authorizationVerification{candidate: candidate, admission: admission}, nil
			})
			if delayed {
				if err == nil {
					t.Fatal("expired NRAS evidence was published")
				}
				if _, ok := store.acquire(key); ok {
					t.Fatal("failed admission cached authorization")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Advancing past JWT and certificate dates cannot force renewal or prevent
			// report promotion. No connection needs to remain open for cache reuse.
			at = now.AddDate(10000, 0, 0)
			var calls atomic.Int32
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					current, _, err := store.load(t.Context(), key, nil, nil, func(context.Context) (authorizationVerification, error) {
						calls.Add(1)
						return authorizationVerification{candidate: candidate}, nil
					})
					if err != nil {
						t.Error(err)
						return
					}
					if current.generation != value.generation {
						t.Error("time replaced authorization")
					}
					if !store.promote(key, current.generation, "authenticated response") {
						t.Error("time prevented promotion")
					}
				})
			}
			wg.Wait()
			if calls.Load() != 0 {
				t.Fatal("cache hit reattested after evidence expiration")
			}
			if len(store.snapshots()) != 1 {
				t.Fatal("age hid cached report")
			}
		})
	}
}
