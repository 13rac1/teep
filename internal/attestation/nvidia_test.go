package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
func makeTestJWT(t *testing.T, key *ecdsa.PrivateKey, kid string, _ bool, nonce, issuer string, exp time.Time) string {
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
		w.Write(body)
	}))
}

// setupTestKeyfunc creates a JWKS server and registers it with the global
// keyfunc cache. Returns the server URL. Cleanup is handled by t.Cleanup.
func setupTestKeyfunc(t *testing.T, key *ecdsa.PublicKey, kid string) string {
	t.Helper()
	srv := makeTestJWKSServer(t, key, kid)
	t.Cleanup(func() {
		srv.Close()
		resetJWKS()
	})
	return srv.URL
}

// TestVerifyJWT_ValidToken verifies a correctly-signed JWT passes all checks.
func TestVerifyJWT_ValidToken(t *testing.T) {
	key := generateTestECKey(t)
	kid := "test-kid-1"
	nonce := NewNonce()

	jwksURL := setupTestKeyfunc(t, &key.PublicKey, kid)
	tokenStr := makeTestJWT(t, key, kid, true, nonce.Hex(), "https://test.nvidia.com", time.Now().Add(time.Hour))

	kf, err := getOrCreateKeyfunc(context.Background(), jwksURL)
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

	jwksURL := setupTestKeyfunc(t, &key.PublicKey, kid)
	tokenStr := makeTestJWT(t, key, kid, true, "", "https://test.nvidia.com", time.Now().Add(-time.Hour))

	kf, err := getOrCreateKeyfunc(context.Background(), jwksURL)
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

	jwksURL := setupTestKeyfunc(t, &verifyKey.PublicKey, kid)
	tokenStr := makeTestJWT(t, signingKey, kid, true, "", "test", time.Now().Add(time.Hour))

	kf, err := getOrCreateKeyfunc(context.Background(), jwksURL)
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

	jwksURL := setupTestKeyfunc(t, &key.PublicKey, "key-B")
	tokenStr := makeTestJWT(t, key, "key-A", true, "", "test", time.Now().Add(time.Hour))

	kf, err := getOrCreateKeyfunc(context.Background(), jwksURL)
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

	jwksURL := setupTestKeyfunc(t, &key.PublicKey, kid)
	jwtStr := makeTestJWT(t, key, kid, true, nonce.Hex(), "https://nras.attestation.nvidia.com", time.Now().Add(time.Hour))

	result := verifyNVIDIAJWT(context.Background(), jwtStr, jwksURL)
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
	jwksURL := setupTestKeyfunc(t, &key.PublicKey, "empty-test-kid")

	result := verifyNVIDIAJWT(context.Background(), "", jwksURL)
	if result.SignatureErr == nil && result.ClaimsErr == nil {
		t.Error("expected error for empty JWT, got nil")
	}
}

// TestExtractNRASJWT verifies the NRAS response parsing.
func TestExtractNRASJWT(t *testing.T) {
	// Valid: array of [type, token] pairs.
	extracted, err := extractNRASJWT(`[["JWT","eyJhbGciOi.payload.sig"]]`)
	if err != nil {
		t.Fatalf("extractNRASJWT valid: %v", err)
	}
	if extracted != "eyJhbGciOi.payload.sig" {
		t.Errorf("got %q, want %q", extracted, "eyJhbGciOi.payload.sig")
	}

	// Multiple entries: takes the JWT one.
	extracted, err = extractNRASJWT(`[["OTHER","foo"],["JWT","eyJhbGciOi.p.s"]]`)
	if err != nil {
		t.Fatalf("extractNRASJWT multi: %v", err)
	}
	if extracted != "eyJhbGciOi.p.s" {
		t.Errorf("got %q", extracted)
	}

	// No JWT entry.
	_, err = extractNRASJWT(`[["OTHER","foo"]]`)
	if err == nil {
		t.Error("expected error for no JWT entry, got nil")
	}

	// Not JSON.
	_, err = extractNRASJWT(`not-json`)
	if err == nil {
		t.Error("expected error for non-JSON, got nil")
	}

	// Empty array.
	_, err = extractNRASJWT(`[]`)
	if err == nil {
		t.Error("expected error for empty array, got nil")
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
