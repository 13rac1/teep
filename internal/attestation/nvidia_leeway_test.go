package attestation

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNVIDIAJWTLeeway(t *testing.T) {
	key := generateTestECKey(t)
	jwks := makeJWKSBody(t, &key.PublicKey, "test")
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()
	verifier := NewNVIDIAVerifier("", srv.URL)
	defer verifier.Shutdown()
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                 string
		nbf, exp             time.Duration
		missingExp, wrongKey bool
		want                 error
	}{
		{name: "current", nbf: -time.Second, exp: time.Hour},
		{name: "early_within_leeway", nbf: 9 * time.Second, exp: time.Hour},
		{name: "early_boundary", nbf: 10 * time.Second, exp: time.Hour},
		{name: "too_early", nbf: 11 * time.Second, exp: time.Hour, want: jwt.ErrTokenNotValidYet},
		{name: "expired_within_leeway", nbf: -time.Hour, exp: -9 * time.Second},
		{name: "expiry_boundary", nbf: -time.Hour, exp: -10 * time.Second, want: jwt.ErrTokenExpired},
		{name: "too_late", nbf: -time.Hour, exp: -11 * time.Second, want: jwt.ErrTokenExpired},
		{name: "missing_expiration", missingExp: true, want: jwt.ErrTokenRequiredClaimMissing},
		{name: "wrong_signature_within_leeway", nbf: 9 * time.Second, exp: time.Hour, wrongKey: true, want: jwt.ErrTokenSignatureInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := &nvidiaClaims{RegisteredClaims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now.Add(tc.nbf)),
				ExpiresAt: jwt.NewNumericDate(now.Add(tc.exp)),
			}, OverallResult: true}
			if tc.missingExp {
				claims.ExpiresAt = nil
			}
			token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
			token.Header["kid"] = "test"
			signingKey := key
			if tc.wrongKey {
				signingKey = generateTestECKey(t)
			}
			signed, err := token.SignedString(signingKey)
			if err != nil {
				t.Fatal(err)
			}
			result := verifier.verifyNVIDIAJWT(t.Context(), signed, srv.URL, srv.Client(), jwt.WithTimeFunc(func() time.Time { return now }))
			err = errors.Join(result.ClaimsErr, result.SignatureErr)
			if !errors.Is(err, tc.want) {
				t.Fatalf("verification error=%v want=%v", err, tc.want)
			}
			bound, ok := result.Validity.Expiry()
			if tc.want != nil {
				if ok {
					t.Fatal("invalid JWT supplied authorization validity")
				}
				return
			}
			if !ok || !bound.Equal(now.Add(tc.exp+10*time.Second)) {
				t.Fatal("authorization bound does not include exactly 10 seconds of leeway")
			}
			if !result.ExpiresAt.Equal(now.Add(tc.exp)) {
				t.Fatal("diagnostic expiration changed")
			}
			reportBound, ok := reportEvidenceValidity(&ReportInput{NvidiaNRAS: result}, []FactorResult{{Name: FactorNvidiaNRAS, Status: Pass}}).Expiry()
			if !ok || !reportBound.Equal(bound) {
				t.Fatal("report lost JWT authorization bound")
			}
		})
	}
	if requests.Load() != 1 {
		t.Fatalf("claim failures caused extra JWKS requests: %d", requests.Load())
	}
}
