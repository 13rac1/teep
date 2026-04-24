package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateTestECKey generates a P-384 ECDSA key pair for test JWTs,
// matching what NVIDIA NRAS uses in production.
func generateTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// makeTestJWT creates a signed JWT with the given claims using the provided EC key.
func makeTestJWT(t *testing.T, key *ecdsa.PrivateKey, kid, nonce, issuer string, exp time.Time) string {
	t.Helper()
	claims := &nvidiaClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		OverallResult: true,
		Nonce:         nonce,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

// makeJWKSBody returns JSON for a JWKS containing the given EC public key.
func makeJWKSBody(t *testing.T, key *ecdsa.PublicKey, kid string) []byte {
	t.Helper()
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()
	for len(xBytes) < byteLen {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < byteLen {
		yBytes = append([]byte{0}, yBytes...)
	}
	jwks := map[string]any{
		"keys": []map[string]string{
			{
				"kty": "EC",
				"kid": kid,
				"crv": "P-384",
				"x":   base64.RawURLEncoding.EncodeToString(xBytes),
				"y":   base64.RawURLEncoding.EncodeToString(yBytes),
				"alg": "ES384",
				"use": "sig",
			},
		},
	}
	body, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return body
}

// makeTestJWKSServer starts an httptest.Server serving a JWKS for the given key.
func makeTestJWKSServer(t *testing.T, key *ecdsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	body := makeJWKSBody(t, key, kid)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

// setupTestVerifier creates a JWKS server and returns an NVIDIAVerifier
// configured to use it. Cleanup is handled by t.Cleanup.
func setupTestVerifier(t *testing.T, key *ecdsa.PublicKey, kid string) (v *NVIDIAVerifier, jwksURL string) {
	t.Helper()
	srv := makeTestJWKSServer(t, key, kid)
	v = NewNVIDIAVerifier("", srv.URL)
	t.Cleanup(func() {
		srv.Close()
		v.Shutdown()
	})
	return v, srv.URL
}

func TestGetOrCreateKeyfunc_RefreshesAfterTTL(t *testing.T) {
	key := generateTestECKey(t)
	kid := "ttl-kid"
	body := makeJWKSBody(t, &key.PublicKey, kid)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	v := NewNVIDIAVerifier("", srv.URL)
	v.cacheTTL = 0 // force immediate expiry
	t.Cleanup(v.Shutdown)

	if _, err := v.getOrCreateKeyfunc(t.Context(), srv.URL, nil); err != nil {
		t.Fatalf("first getOrCreateKeyfunc: %v", err)
	}
	if _, err := v.getOrCreateKeyfunc(t.Context(), srv.URL, nil); err != nil {
		t.Fatalf("second getOrCreateKeyfunc: %v", err)
	}

	if got := calls.Load(); got != 2 {
		t.Fatalf("expected exactly 2 JWKS fetches after forced refresh, got %d", got)
	}
}

// TestShouldRefetchJWKS_Cooldown verifies that a freshly-fetched JWKS entry
// cannot be immediately invalidated, preventing cache thrashing from malformed
// JWTs that trigger ErrTokenUnverifiable.
func TestShouldRefetchJWKS_Cooldown(t *testing.T) {
	key := generateTestECKey(t)
	var calls atomic.Int32
	body := makeJWKSBody(t, &key.PublicKey, "cooldown-kid")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	v := NewNVIDIAVerifier("", srv.URL)
	t.Cleanup(v.Shutdown)

	if _, err := v.getOrCreateKeyfunc(t.Context(), srv.URL, srv.Client()); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 fetch after population, got %d", got)
	}

	// Immediate invalidation must be suppressed by the cooldown.
	if v.shouldRefetchJWKS(srv.URL) {
		t.Error("shouldRefetchJWKS: expected false (within cooldown), got true")
	}

	// Cache should still be populated; no new fetch.
	if _, err := v.getOrCreateKeyfunc(t.Context(), srv.URL, srv.Client()); err != nil {
		t.Fatalf("post-suppressed-invalidation fetch: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("expected still 1 fetch after suppressed invalidation, got %d", got)
	}
}

// TestShouldRefetchJWKS_AllowsAfterCooldown verifies that invalidation
// succeeds once the cooldown has elapsed (simulated via cooldown=0).
func TestShouldRefetchJWKS_AllowsAfterCooldown(t *testing.T) {
	key := generateTestECKey(t)
	var calls atomic.Int32
	body := makeJWKSBody(t, &key.PublicKey, "post-cooldown-kid")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	v := NewNVIDIAVerifier("", srv.URL)
	v.cooldown = 0
	t.Cleanup(v.Shutdown)

	if _, err := v.getOrCreateKeyfunc(t.Context(), srv.URL, srv.Client()); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	// With cooldown=0, invalidation must succeed.
	if !v.shouldRefetchJWKS(srv.URL) {
		t.Error("shouldRefetchJWKS: expected true (cooldown elapsed), got false")
	}

	// Next fetch must hit the server again.
	if _, err := v.getOrCreateKeyfunc(t.Context(), srv.URL, srv.Client()); err != nil {
		t.Fatalf("post-invalidation fetch: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("expected 2 fetches after invalidation, got %d", got)
	}
}

// TestVerifyJWT_ValidToken verifies a correctly-signed JWT passes all checks.
func TestVerifyJWT_ValidToken(t *testing.T) {
	key := generateTestECKey(t)
	kid := "test-kid-1"
	nonce := NewNonce()

	v, jwksURL := setupTestVerifier(t, &key.PublicKey, kid)
	tokenStr := makeTestJWT(t, key, kid, nonce.Hex(), "https://test.nvidia.com", time.Now().Add(time.Hour))

	kf, err := v.getOrCreateKeyfunc(t.Context(), jwksURL, nil)
	if err != nil {
		t.Fatalf("getOrCreateKeyfunc: %v", err)
	}

	claims := &nvidiaClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, kf.Keyfunc,
		jwt.WithValidMethods([]string{"ES384"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	if !token.Valid {
		t.Error("token is not valid")
	}
	if !claims.OverallResult {
		t.Error("OverallResult: got false, want true")
	}
	if claims.Nonce != nonce.Hex() {
		t.Errorf("Nonce: got %q, want %q", claims.Nonce, nonce.Hex())
	}
}

// TestVerifyJWT_ExpiredToken verifies an expired JWT fails claims validation.
func TestVerifyJWT_ExpiredToken(t *testing.T) {
	key := generateTestECKey(t)
	kid := "test-kid-2"

	v, jwksURL := setupTestVerifier(t, &key.PublicKey, kid)
	tokenStr := makeTestJWT(t, key, kid, "", "https://test.nvidia.com", time.Now().Add(-time.Hour))

	kf, err := v.getOrCreateKeyfunc(t.Context(), jwksURL, nil)
	if err != nil {
		t.Fatalf("getOrCreateKeyfunc: %v", err)
	}

	claims := &nvidiaClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, kf.Keyfunc,
		jwt.WithValidMethods([]string{"ES384"}),
		jwt.WithExpirationRequired(),
	)
	if err == nil {
		t.Error("expired token: expected error, got nil")
	}
	if isSignatureError(err) {
		t.Errorf("expired token: error should NOT be a signature error: %v", err)
	}
}

// TestVerifyJWT_WrongKey verifies that a JWT signed with a different key fails.
func TestVerifyJWT_WrongKey(t *testing.T) {
	signingKey := generateTestECKey(t)
	verifyKey := generateTestECKey(t) // different key
	kid := "test-kid-3"

	v, jwksURL := setupTestVerifier(t, &verifyKey.PublicKey, kid)
	tokenStr := makeTestJWT(t, signingKey, kid, "", "test", time.Now().Add(time.Hour))

	kf, err := v.getOrCreateKeyfunc(t.Context(), jwksURL, nil)
	if err != nil {
		t.Fatalf("getOrCreateKeyfunc: %v", err)
	}

	claims := &nvidiaClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, kf.Keyfunc,
		jwt.WithValidMethods([]string{"ES384"}),
	)
	if err == nil {
		t.Error("wrong key: expected error, got nil")
	}
	if !isSignatureError(err) {
		t.Errorf("wrong key error should be a signature error: %v", err)
	}
}

// TestVerifyJWT_UnknownKid verifies error when kid is not in JWKS.
func TestVerifyJWT_UnknownKid(t *testing.T) {
	key := generateTestECKey(t)

	v, jwksURL := setupTestVerifier(t, &key.PublicKey, "key-B")
	tokenStr := makeTestJWT(t, key, "key-A", "", "test", time.Now().Add(time.Hour))

	kf, err := v.getOrCreateKeyfunc(t.Context(), jwksURL, nil)
	if err != nil {
		t.Fatalf("getOrCreateKeyfunc: %v", err)
	}

	claims := &nvidiaClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, kf.Keyfunc,
		jwt.WithValidMethods([]string{"ES384"}),
	)
	if err == nil {
		t.Error("unknown kid: expected error, got nil")
	}
}

// TestIsSignatureError confirms the error categorisation logic.
func TestIsSignatureError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrTokenSignatureInvalid", jwt.ErrTokenSignatureInvalid, true},
		{"ErrTokenUnverifiable", jwt.ErrTokenUnverifiable, true},
		{"ErrTokenMalformed", jwt.ErrTokenMalformed, true},
		{"ErrTokenExpired", jwt.ErrTokenExpired, false},
		{"ErrTokenInvalidClaims", jwt.ErrTokenInvalidClaims, false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isSignatureError(tc.err)
			if got != tc.want {
				t.Errorf("isSignatureError(%v): got %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestExtractPartialClaims verifies claim extraction works with nil ExpiresAt.
func TestExtractPartialClaims(t *testing.T) {
	claims := &nvidiaClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: nil,
		},
		OverallResult: true,
		Nonce:         "abc123",
	}
	result := &NvidiaVerifyResult{}
	extractPartialClaims(claims, result)

	if result.Issuer != "test-issuer" {
		t.Errorf("Issuer: got %q, want %q", result.Issuer, "test-issuer")
	}
	if !result.OverallResult {
		t.Error("OverallResult: got false, want true")
	}
	if result.Nonce != "abc123" {
		t.Errorf("Nonce: got %q, want %q", result.Nonce, "abc123")
	}
	if !result.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt should be zero when ExpiresAt claim is nil")
	}
}

// TestVerifyNVIDIAJWT_Success verifies the full verifyNVIDIAJWT flow with
// a mock JWKS server.
func TestVerifyNVIDIAJWT_Success(t *testing.T) {
	key := generateTestECKey(t)
	kid := "nras-test-kid"
	nonce := NewNonce()

	v, jwksURL := setupTestVerifier(t, &key.PublicKey, kid)
	jwtStr := makeTestJWT(t, key, kid, nonce.Hex(), "https://nras.attestation.nvidia.com", time.Now().Add(time.Hour))

	result := v.verifyNVIDIAJWT(t.Context(), jwtStr, jwksURL, nil)
	if result.SignatureErr != nil {
		t.Errorf("SignatureErr: %v", result.SignatureErr)
	}
	if result.ClaimsErr != nil {
		t.Errorf("ClaimsErr: %v", result.ClaimsErr)
	}
	if !result.OverallResult {
		t.Error("OverallResult: got false, want true")
	}
	if result.Format != "JWT" {
		t.Errorf("Format: got %q, want %q", result.Format, "JWT")
	}
}

// TestVerifyNVIDIAJWT_EmptyToken verifies error on empty JWT string.
func TestVerifyNVIDIAJWT_EmptyToken(t *testing.T) {
	key := generateTestECKey(t)
	v, jwksURL := setupTestVerifier(t, &key.PublicKey, "empty-test-kid")

	result := v.verifyNVIDIAJWT(t.Context(), "", jwksURL, nil)
	if result.SignatureErr == nil && result.ClaimsErr == nil {
		t.Error("expected error for empty JWT, got nil")
	}
}

// TestVerifyNVIDIAJWT_RetryOnUnknownKid verifies that verifyNVIDIAJWT
// invalidates the cache and retries when the JWT's kid is not in the cached
// keyset, recovering from NVIDIA key rotations without waiting for TTL expiry.
func TestVerifyNVIDIAJWT_RetryOnUnknownKid(t *testing.T) {
	correctKey := generateTestECKey(t)
	wrongKey := generateTestECKey(t)
	kid := "rotated-kid"
	nonce := NewNonce()

	var callCount atomic.Int32
	wrongBody := makeJWKSBody(t, &wrongKey.PublicKey, "wrong-kid")
	rightBody := makeJWKSBody(t, &correctKey.PublicKey, kid)

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if callCount.Add(1) == 1 {
			_, _ = w.Write(wrongBody) // first fetch: stale keyset (kid not present)
		} else {
			_, _ = w.Write(rightBody) // second fetch: updated keyset after rotation
		}
	}))
	defer jwksSrv.Close()

	v := NewNVIDIAVerifier("", jwksSrv.URL)
	v.cooldown = 0 // allow immediate re-fetch
	t.Cleanup(v.Shutdown)

	jwtStr := makeTestJWT(t, correctKey, kid, nonce.Hex(), "https://nras.attestation.nvidia.com", time.Now().Add(time.Hour))

	result := v.verifyNVIDIAJWT(t.Context(), jwtStr, jwksSrv.URL, jwksSrv.Client())
	t.Logf("callCount=%d SignatureErr=%v ClaimsErr=%v", callCount.Load(), result.SignatureErr, result.ClaimsErr)

	if result.SignatureErr != nil {
		t.Errorf("SignatureErr: %v", result.SignatureErr)
	}
	if result.ClaimsErr != nil {
		t.Errorf("ClaimsErr: %v", result.ClaimsErr)
	}
	if callCount.Load() < 2 {
		t.Errorf("expected at least 2 JWKS fetches (retry on unknown kid), got %d", callCount.Load())
	}
}

// TestExtractNRASJWT verifies the NRAS response parsing.
func TestExtractNRASJWT(t *testing.T) {
	// Valid: array of [type, token] pairs.
	extracted, perGPU, err := extractNRASJWT(context.Background(), `[["JWT","eyJhbGciOi.payload.sig"]]`)
	if err != nil {
		t.Fatalf("extractNRASJWT valid: %v", err)
	}
	if extracted != "eyJhbGciOi.payload.sig" {
		t.Errorf("got %q, want %q", extracted, "eyJhbGciOi.payload.sig")
	}
	if perGPU != nil {
		t.Errorf("perGPU = %v, want nil", perGPU)
	}

	// Multiple entries: takes the JWT one.
	extracted, _, err = extractNRASJWT(context.Background(), `[["OTHER","foo"],["JWT","eyJhbGciOi.p.s"]]`)
	if err != nil {
		t.Fatalf("extractNRASJWT multi: %v", err)
	}
	if extracted != "eyJhbGciOi.p.s" {
		t.Errorf("got %q", extracted)
	}

	// With per-GPU JWTs (NRAS v3 format).
	extracted, perGPU, err = extractNRASJWT(context.Background(), `[["JWT","eyJ.overall.sig"],{"GPU-0":"eyJ.gpu0.sig","GPU-1":"eyJ.gpu1.sig"}]`)
	if err != nil {
		t.Fatalf("extractNRASJWT v3: %v", err)
	}
	if extracted != "eyJ.overall.sig" {
		t.Errorf("overall JWT = %q, want %q", extracted, "eyJ.overall.sig")
	}
	if len(perGPU) != 2 {
		t.Fatalf("perGPU count = %d, want 2", len(perGPU))
	}
	if perGPU["GPU-0"] != "eyJ.gpu0.sig" {
		t.Errorf("GPU-0 = %q", perGPU["GPU-0"])
	}

	// No JWT entry.
	_, _, err = extractNRASJWT(context.Background(), `[["OTHER","foo"]]`)
	if err == nil {
		t.Error("expected error for no JWT entry, got nil")
	}

	// Not JSON.
	_, _, err = extractNRASJWT(context.Background(), `not-json`)
	if err == nil {
		t.Error("expected error for non-JSON, got nil")
	}

	// Empty array.
	_, _, err = extractNRASJWT(context.Background(), `[]`)
	if err == nil {
		t.Error("expected error for empty array, got nil")
	}
}

// --------------------------------------------------------------------------
// VerifyNVIDIAPayload dispatcher tests
// --------------------------------------------------------------------------

func TestVerifyNVIDIAPayload_EmptyPayload(t *testing.T) {
	result := VerifyNVIDIAPayload(context.Background(), "", NewNonce())
	if result.SignatureErr == nil {
		t.Fatal("expected error for empty payload")
	}
	t.Logf("got expected error: %v", result.SignatureErr)
}

func TestVerifyNVIDIAPayload_NonEATPayload(t *testing.T) {
	// JWT-style payload starts with 'e' (base64 header), not '{'
	result := VerifyNVIDIAPayload(context.Background(), "eyJhbGciOiJSUzI1NiJ9.payload.sig", NewNonce())
	if result.SignatureErr == nil {
		t.Fatal("expected error for non-EAT payload")
	}
	if result.Format != "" {
		t.Errorf("Format = %q, want empty (not yet detected)", result.Format)
	}
	t.Logf("got expected error: %v", result.SignatureErr)
}

func TestVerifyNVIDIAPayload_EATDispatch(t *testing.T) {
	nonce := NewNonce()
	// Minimal EAT payload with matching nonce but no valid certs/evidence.
	// verifyNVIDIAEAT will detect the format but fail on GPU cert verification.
	payload := fmt.Sprintf(`{"arch":"HOPPER","nonce":%q,"evidence_list":[{"arch":"HOPPER","certificate":"","evidence":""}]}`, nonce.Hex())

	result := VerifyNVIDIAPayload(context.Background(), payload, nonce)
	// EAT format should be detected even though verification fails.
	if result.Format != "EAT" {
		t.Errorf("Format = %q, want EAT", result.Format)
	}
	if result.Arch != "HOPPER" {
		t.Errorf("Arch = %q, want HOPPER", result.Arch)
	}
	if result.GPUCount != 1 {
		t.Errorf("GPUCount = %d, want 1", result.GPUCount)
	}
	// Cert/evidence verification will fail — that's expected.
	if result.SignatureErr == nil {
		t.Log("SignatureErr is nil — cert verification passed unexpectedly")
	} else {
		t.Logf("expected cert verification error: %v", result.SignatureErr)
	}
}

// TestTruncate verifies the truncate helper.
func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate short: got %q, want %q", got, "hello")
	}
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("truncate long: got %q, want %q", got, "hello...")
	}
}

// --------------------------------------------------------------------------
// VerifyNRAS tests (mock NRAS server)
// --------------------------------------------------------------------------

func TestVerifyNRAS_MockSuccess(t *testing.T) {
	key := generateTestECKey(t)
	kid := "nras-mock-kid"
	nonce := NewNonce()

	// Start a JWKS server for JWT verification.
	jwksSrv := makeTestJWKSServer(t, &key.PublicKey, kid)
	defer jwksSrv.Close()

	// Create a signed JWT that NRAS would return.
	jwtStr := makeTestJWT(t, key, kid, nonce.Hex(), "https://nras.attestation.nvidia.com", time.Now().Add(time.Hour))

	// Build the NRAS response: a JSON array of [type, token] pairs.
	nrasBody, err := json.Marshal([][]string{{"JWT", jwtStr}})
	if err != nil {
		t.Fatalf("marshal NRAS response: %v", err)
	}

	// Start a mock NRAS server.
	nrasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("NRAS mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(nrasBody)
	}))
	defer nrasSrv.Close()

	v := NewNVIDIAVerifier(nrasSrv.URL, jwksSrv.URL)
	t.Cleanup(v.Shutdown)

	result := v.VerifyNRAS(context.Background(), `{"arch":"HOPPER"}`, nil)

	t.Logf("result: Format=%s SignatureErr=%v ClaimsErr=%v OverallResult=%v",
		result.Format, result.SignatureErr, result.ClaimsErr, result.OverallResult)

	if result.SignatureErr != nil {
		t.Errorf("SignatureErr: %v", result.SignatureErr)
	}
	if result.ClaimsErr != nil {
		t.Errorf("ClaimsErr: %v", result.ClaimsErr)
	}
	if result.Format != "JWT" {
		t.Errorf("Format = %q, want JWT", result.Format)
	}
	if !result.OverallResult {
		t.Error("OverallResult = false, want true")
	}
}

func TestVerifyNRAS_ServerError(t *testing.T) {
	nrasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("NRAS mock: %s %s → 500", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer nrasSrv.Close()

	v := NewNVIDIAVerifier(nrasSrv.URL, "")
	result := v.VerifyNRAS(context.Background(), `{"arch":"HOPPER"}`, nil)

	t.Logf("result: Format=%s SignatureErr=%v ClaimsErr=%v", result.Format, result.SignatureErr, result.ClaimsErr)

	if result.ClaimsErr == nil {
		t.Error("expected ClaimsErr for 500 response, got nil")
	}
}

func TestVerifyNRAS_EmptyResponse(t *testing.T) {
	nrasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("NRAS mock: %s %s → 200 empty", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		// Empty body.
	}))
	defer nrasSrv.Close()

	v := NewNVIDIAVerifier(nrasSrv.URL, "")
	result := v.VerifyNRAS(context.Background(), `{"arch":"HOPPER"}`, nil)

	t.Logf("result: Format=%s SignatureErr=%v ClaimsErr=%v", result.Format, result.SignatureErr, result.ClaimsErr)

	if result.SignatureErr == nil {
		t.Error("expected SignatureErr for empty response, got nil")
	}
}

// TestExtractGPUDiags verifies per-GPU JWT payload decoding.
func TestExtractGPUDiags(t *testing.T) {
	// Build a minimal per-GPU JWT payload (no signature verification needed).
	claims := map[string]any{
		"measres":                     "success",
		"hwmodel":                     "GH100",
		"x-nvidia-gpu-driver-version": "570.172.08",
		"x-nvidia-gpu-vbios-version":  "96.00.CF.00.02",
		"x-nvidia-gpu-attestation-report-nonce-match": true,
		"secboot": true,
		"dbgstat": "disabled",
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	// Construct a fake JWT: header.payload.signature
	fakeJWT := "eyJhbGciOiJFUzM4NCJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".fakesig"

	perGPU := map[string]string{
		"GPU-0": fakeJWT,
		"GPU-1": fakeJWT,
	}

	diags := extractGPUDiags(context.Background(), perGPU)
	t.Logf("diags: %+v", diags)

	if len(diags) != 2 {
		t.Fatalf("got %d diags, want 2", len(diags))
	}
	// Sorted by GPU ID.
	if diags[0].GPUID != "GPU-0" {
		t.Errorf("diags[0].GPUID = %q", diags[0].GPUID)
	}
	if diags[0].MeasRes != "success" {
		t.Errorf("MeasRes = %q, want success", diags[0].MeasRes)
	}
	if diags[0].HWModel != "GH100" {
		t.Errorf("HWModel = %q, want GH100", diags[0].HWModel)
	}
	if diags[0].DriverVersion != "570.172.08" {
		t.Errorf("DriverVersion = %q", diags[0].DriverVersion)
	}
	if !diags[0].NonceMatch {
		t.Error("NonceMatch = false, want true")
	}
	if !diags[0].SecBoot {
		t.Error("SecBoot = false, want true")
	}
	if diags[0].DbgStat != "disabled" {
		t.Errorf("DbgStat = %q", diags[0].DbgStat)
	}

	// Nil map returns nil.
	if got := extractGPUDiags(context.Background(), nil); got != nil {
		t.Errorf("nil map returned %v", got)
	}

	// Invalid JWT payload.
	diags = extractGPUDiags(context.Background(), map[string]string{"GPU-0": "not-a-jwt"})
	if len(diags) != 1 {
		t.Fatalf("got %d diags, want 1", len(diags))
	}
	if !strings.Contains(diags[0].MeasRes, "decode error") {
		t.Errorf("expected decode error, got %q", diags[0].MeasRes)
	}
}

func TestAllSameError(t *testing.T) {
	tests := []struct {
		name  string
		diags []NRASGPUDiag
		want  bool
	}{
		{
			name:  "empty slice",
			diags: nil,
			want:  false,
		},
		{
			name:  "single diag (less than 2)",
			diags: []NRASGPUDiag{{ErrorDetails: "some error"}},
			want:  false,
		},
		{
			name:  "two diags same non-empty error",
			diags: []NRASGPUDiag{{ErrorDetails: "OOM"}, {ErrorDetails: "OOM"}},
			want:  true,
		},
		{
			name:  "two diags different errors",
			diags: []NRASGPUDiag{{ErrorDetails: "OOM"}, {ErrorDetails: "timeout"}},
			want:  false,
		},
		{
			name:  "two diags both empty error",
			diags: []NRASGPUDiag{{ErrorDetails: ""}, {ErrorDetails: ""}},
			want:  false, // first == "" so returns false
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allSameError(tt.diags)
			t.Logf("allSameError(%d diags) = %v", len(tt.diags), got)
			if got != tt.want {
				t.Errorf("allSameError = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNRASDiagDetail(t *testing.T) {
	tests := []struct {
		name     string
		result   *NvidiaVerifyResult
		wantSubs []string
	}{
		{
			name:     "no GPU diags",
			result:   &NvidiaVerifyResult{},
			wantSubs: []string{"NRAS result: false"},
		},
		{
			name: "all GPUs same error",
			result: &NvidiaVerifyResult{
				GPUDiags: []NRASGPUDiag{
					{GPUID: "GPU-0", ErrorDetails: "measurement mismatch"},
					{GPUID: "GPU-1", ErrorDetails: "measurement mismatch"},
				},
			},
			wantSubs: []string{"NRAS result: false", "2 GPUs", "measurement mismatch"},
		},
		{
			name: "different errors per GPU",
			result: &NvidiaVerifyResult{
				GPUDiags: []NRASGPUDiag{
					{GPUID: "GPU-0", ErrorDetails: "error A"},
					{GPUID: "GPU-1", ErrorDetails: "error B"},
				},
			},
			wantSubs: []string{"NRAS result: false", "GPU-0", "error A", "GPU-1", "error B"},
		},
		{
			name: "GPU with measres (no error)",
			result: &NvidiaVerifyResult{
				GPUDiags: []NRASGPUDiag{
					{GPUID: "GPU-0", MeasRes: "FAIL", DriverVersion: "570.0", HWModel: "GH100"},
					{GPUID: "GPU-1", MeasRes: "OK", DriverVersion: "570.0", HWModel: "GH100"},
				},
			},
			wantSubs: []string{"NRAS result: false", "GPU-0", "measres=FAIL"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nrasDiagDetail(tt.result)
			t.Logf("nrasDiagDetail = %q", got)
			for _, sub := range tt.wantSubs {
				if !strings.Contains(got, sub) {
					t.Errorf("detail %q missing %q", got, sub)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// nvidiaErrorMessage
// ---------------------------------------------------------------------------

func TestNvidiaErrorMessage_NoKey(t *testing.T) {
	claims := map[string]any{"foo": "bar"}
	got := nvidiaErrorMessage(claims)
	if got != "" {
		t.Errorf("nvidiaErrorMessage (no key) = %q, want empty", got)
	}
}

func TestNvidiaErrorMessage_NotMap(t *testing.T) {
	claims := map[string]any{"x-nvidia-error-details": "raw string value"}
	got := nvidiaErrorMessage(claims)
	if got != "raw string value" {
		t.Errorf("nvidiaErrorMessage (not-map) = %q, want %q", got, "raw string value")
	}
}

func TestNvidiaErrorMessage_WithMessage(t *testing.T) {
	claims := map[string]any{
		"x-nvidia-error-details": map[string]any{
			"message": "GPU attestation failed",
		},
	}
	got := nvidiaErrorMessage(claims)
	if got != "GPU attestation failed" {
		t.Errorf("nvidiaErrorMessage (with message) = %q, want %q", got, "GPU attestation failed")
	}
}

func TestNvidiaErrorMessage_WithDescription(t *testing.T) {
	claims := map[string]any{
		"x-nvidia-error-details": map[string]any{
			"description": "certificate expired",
		},
	}
	got := nvidiaErrorMessage(claims)
	if got != "certificate expired" {
		t.Errorf("nvidiaErrorMessage (with description) = %q, want %q", got, "certificate expired")
	}
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

func TestShutdown(t *testing.T) {
	v := DefaultNVIDIAVerifier()
	v.Shutdown() // must not panic; idempotent
	v.Shutdown()
	t.Log("Shutdown completed twice without panic")
}

// ---------------------------------------------------------------------------
// jsonString / jsonBool utility functions
// ---------------------------------------------------------------------------

func TestJSONString_MissingKey(t *testing.T) {
	m := map[string]any{"other": "value"}
	if got := jsonString(m, "missing"); got != "" {
		t.Errorf("jsonString missing key = %q, want \"\"", got)
	}
}

func TestJSONString_StringValue(t *testing.T) {
	m := map[string]any{"k": "hello"}
	if got := jsonString(m, "k"); got != "hello" {
		t.Errorf("jsonString string value = %q, want \"hello\"", got)
	}
}

func TestJSONString_NonStringValue(t *testing.T) {
	// Non-string value triggers the fmt.Sprintf fallback branch.
	m := map[string]any{"k": 42}
	got := jsonString(m, "k")
	if got != "42" {
		t.Errorf("jsonString non-string = %q, want \"42\"", got)
	}
}

func TestJSONBool_MissingKey(t *testing.T) {
	m := map[string]any{"other": true}
	if got := jsonBool(m, "missing"); got {
		t.Error("jsonBool missing key should return false")
	}
}

func TestJSONBool_TrueValue(t *testing.T) {
	m := map[string]any{"k": true}
	if got := jsonBool(m, "k"); !got {
		t.Error("jsonBool true value should return true")
	}
}

func TestJSONBool_NonBoolValue(t *testing.T) {
	// Non-bool value triggers the type-assertion failure branch.
	m := map[string]any{"k": "yes"}
	if got := jsonBool(m, "k"); got {
		t.Error("jsonBool non-bool value should return false")
	}
}

// TestEvictOldestLocked verifies that evictOldestLocked removes the oldest
// entry when the cache reaches maxJWKSInstances capacity.
func TestEvictOldestLocked(t *testing.T) {
	v := NewNVIDIAVerifier("http://nras.example.com", "http://jwks.example.com")

	// Fill the cache to exactly maxJWKSInstances entries with distinct timestamps.
	base := time.Now()
	v.mu.Lock()
	for i := range maxJWKSInstances {
		url := fmt.Sprintf("http://example.com/jwks/%d", i)
		v.cache[url] = &jwksEntry{createdAt: base.Add(time.Duration(i) * time.Second)}
	}
	v.mu.Unlock()

	t.Logf("cache size before evict: %d (maxJWKSInstances=%d)", len(v.cache), maxJWKSInstances)
	if len(v.cache) != maxJWKSInstances {
		t.Fatalf("expected %d cache entries, got %d", maxJWKSInstances, len(v.cache))
	}

	// Call evictOldestLocked; oldest entry (index 0, earliest timestamp) should go.
	v.mu.Lock()
	v.evictOldestLocked()
	v.mu.Unlock()

	t.Logf("cache size after evict: %d", len(v.cache))
	if len(v.cache) != maxJWKSInstances-1 {
		t.Errorf("after eviction cache size = %d, want %d", len(v.cache), maxJWKSInstances-1)
	}

	// The oldest entry (index 0) should have been removed.
	if _, ok := v.cache["http://example.com/jwks/0"]; ok {
		t.Error("oldest cache entry (index 0) should have been evicted")
	}
}

// TestEvictOldestLocked_BelowCap verifies that evictOldestLocked is a no-op
// when the cache is below capacity.
func TestEvictOldestLocked_BelowCap(t *testing.T) {
	v := NewNVIDIAVerifier("http://nras.example.com", "http://jwks.example.com")
	v.mu.Lock()
	v.cache["http://example.com/jwks/1"] = &jwksEntry{createdAt: time.Now()}
	v.evictOldestLocked() // should be a no-op: len(cache)=1 < maxJWKSInstances
	size := len(v.cache)
	v.mu.Unlock()

	t.Logf("cache size after no-op evict: %d", size)
	if size != 1 {
		t.Errorf("cache size = %d, want 1 (eviction should be no-op below cap)", size)
	}
}

// TestFetchAndCacheJWKS_HTTPError covers the HTTP non-200 response path
// in fetchAndCacheJWKS (lines 274-279).
func TestFetchAndCacheJWKS_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("JWKS server: %s %s → 503", r.Method, r.URL.Path)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	v := NewNVIDIAVerifier("", srv.URL)
	t.Cleanup(v.Shutdown)

	_, err := v.fetchAndCacheJWKS(context.Background(), srv.URL, srv.Client())
	t.Logf("fetchAndCacheJWKS(HTTP 503): err=%v", err)
	if err == nil {
		t.Fatal("expected error for HTTP 503")
	}
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("error should mention 'HTTP 503', got: %v", err)
	}
}

// TestFetchAndCacheJWKS_InvalidJWKS covers the JWKS parse error path
// (lines 285-288). The server returns HTTP 200 but the body is not a valid JWKS.
func TestFetchAndCacheJWKS_InvalidJWKS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("JWKS server: %s %s → 200 invalid JSON", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys": "not-an-array"}`))
	}))
	defer srv.Close()

	v := NewNVIDIAVerifier("", srv.URL)
	t.Cleanup(v.Shutdown)

	_, err := v.fetchAndCacheJWKS(context.Background(), srv.URL, srv.Client())
	t.Logf("fetchAndCacheJWKS(invalid JWKS): err=%v", err)
	if err == nil {
		t.Fatal("expected error for invalid JWKS")
	}
	if !strings.Contains(err.Error(), "parse JWKS") {
		t.Errorf("error should mention 'parse JWKS', got: %v", err)
	}
}

// TestFetchAndCacheJWKS_ClientDoError covers the client.Do error path
// (lines 269-271) by using a transport that always returns an error.
func TestFetchAndCacheJWKS_ClientDoError(t *testing.T) {
	// Create a client whose transport always errors.
	errTransport := &errRoundTripper{err: errors.New("connection refused")}
	client := &http.Client{Transport: errTransport}

	v := NewNVIDIAVerifier("", "http://127.0.0.1:1")
	t.Cleanup(v.Shutdown)

	_, err := v.fetchAndCacheJWKS(context.Background(), "http://127.0.0.1:1/jwks", client)
	t.Logf("fetchAndCacheJWKS(Do error): err=%v", err)
	if err == nil {
		t.Fatal("expected error when client.Do fails")
	}
}

// errRoundTripper is a test helper that always returns an error.
type errRoundTripper struct {
	err error
}

func (e *errRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, e.err
}
