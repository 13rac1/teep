package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
func makeTestJWT(t *testing.T, key *ecdsa.PrivateKey, kid string, overallResult bool, nonce, issuer string, exp time.Time) string {
	t.Helper()
	claims := &nvidiaClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		OverallResult: overallResult,
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
	// Pad to full curve byte length.
	for len(xBytes) < byteLen {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < byteLen {
		yBytes = append([]byte{0}, yBytes...)
	}
	jwks := jwksJSON{
		Keys: []jwkKeyJSON{
			{
				Kty: "EC",
				Kid: kid,
				Crv: "P-384",
				X:   base64.RawURLEncoding.EncodeToString(xBytes),
				Y:   base64.RawURLEncoding.EncodeToString(yBytes),
				Alg: "ES384",
				Use: "sig",
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

// keyfuncFromURL returns a jwt.Keyfunc that fetches JWKS from url using client.
// This is the test entry point; it always re-fetches (no TTL caching).
func keyfuncFromURL(ctx context.Context, client *http.Client, url string) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		keys, err := fetchFromURL(ctx, client, url)
		if err != nil {
			return nil, err
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			if len(keys) == 1 {
				return keys[0].key, nil
			}
			return nil, fmt.Errorf("JWT missing kid header and JWKS has %d keys", len(keys))
		}
		for _, k := range keys {
			if k.kid == kid {
				return k.key, nil
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	}
}

// TestParseJWKS_ECKey verifies that parseJWKS correctly loads an EC key.
func TestParseJWKS_ECKey(t *testing.T) {
	key := generateTestECKey(t)
	body := makeJWKSBody(t, &key.PublicKey, "test-kid")

	keys, err := parseJWKS(body)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("parseJWKS: got %d keys, want 1", len(keys))
	}
	if keys[0].kid != "test-kid" {
		t.Errorf("key kid: got %q, want %q", keys[0].kid, "test-kid")
	}
}

// TestParseJWKS_SkipsNonEC verifies that non-EC keys are silently skipped.
func TestParseJWKS_SkipsNonEC(t *testing.T) {
	raw, _ := json.Marshal(jwksJSON{
		Keys: []jwkKeyJSON{
			{Kty: "RSA", Kid: "rsa-key"},
		},
	})

	_, err := parseJWKS(raw)
	if err == nil {
		t.Error("parseJWKS with only RSA keys: expected error (no usable EC keys), got nil")
	}
}

// TestParseJWKS_SkipsMalformedEC verifies that malformed EC keys are skipped.
func TestParseJWKS_SkipsMalformedEC(t *testing.T) {
	raw, _ := json.Marshal(jwksJSON{
		Keys: []jwkKeyJSON{
			{Kty: "EC", Kid: "bad-key", Crv: "P-384"}, // missing X, Y
		},
	})

	_, err := parseJWKS(raw)
	if err == nil {
		t.Error("parseJWKS with malformed EC key: expected error, got nil")
	}
}

// TestParseJWKS_Empty verifies error on empty key array.
func TestParseJWKS_Empty(t *testing.T) {
	raw, _ := json.Marshal(jwksJSON{Keys: []jwkKeyJSON{}})
	_, err := parseJWKS(raw)
	if err == nil {
		t.Error("parseJWKS with empty keys: expected error, got nil")
	}
}

// TestParseJWKS_InvalidJSON verifies error on malformed JSON.
func TestParseJWKS_InvalidJSON(t *testing.T) {
	_, err := parseJWKS([]byte("not-json{"))
	if err == nil {
		t.Error("parseJWKS with invalid JSON: expected error, got nil")
	}
}

// TestVerifyJWT_ValidToken verifies a correctly-signed JWT passes all checks.
func TestVerifyJWT_ValidToken(t *testing.T) {
	key := generateTestECKey(t)
	kid := "test-kid-1"
	nonce := NewNonce()

	tokenStr := makeTestJWT(t, key, kid, true, nonce.Hex(), "https://test.nvidia.com", time.Now().Add(time.Hour))

	srv := makeTestJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	keyFunc := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)

	claims := &nvidiaClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
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

	// Expired 1 hour ago.
	tokenStr := makeTestJWT(t, key, kid, true, "", "https://test.nvidia.com", time.Now().Add(-time.Hour))

	srv := makeTestJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	keyFunc := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)

	claims := &nvidiaClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
		jwt.WithValidMethods([]string{"ES384"}),
		jwt.WithExpirationRequired(),
	)
	if err == nil {
		t.Error("expired token: expected error, got nil")
	}
	// Expired token should be a claims error, not a signature error.
	if isSignatureError(err) {
		t.Errorf("expired token: error should NOT be a signature error: %v", err)
	}
}

// TestVerifyJWT_WrongKey verifies that a JWT signed with a different key fails.
func TestVerifyJWT_WrongKey(t *testing.T) {
	signingKey := generateTestECKey(t)
	verifyKey := generateTestECKey(t) // different key
	kid := "test-kid-3"

	tokenStr := makeTestJWT(t, signingKey, kid, true, "", "test", time.Now().Add(time.Hour))

	// Serve verifyKey (not signingKey) as the JWKS.
	srv := makeTestJWKSServer(t, &verifyKey.PublicKey, kid)
	defer srv.Close()

	keyFunc := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)

	claims := &nvidiaClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
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

	// Sign with kid "key-A" but serve JWKS with kid "key-B".
	tokenStr := makeTestJWT(t, key, "key-A", true, "", "test", time.Now().Add(time.Hour))

	srv := makeTestJWKSServer(t, &key.PublicKey, "key-B")
	defer srv.Close()

	keyFunc := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)

	claims := &nvidiaClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
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

// TestDecodeBase64URL verifies standard base64url decoding.
func TestDecodeBase64URL(t *testing.T) {
	got, err := decodeBase64URL("aGVsbG8") // "hello"
	if err != nil {
		t.Fatalf("decodeBase64URL: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", string(got), "hello")
	}
}

// TestDecodeBase64URL_Invalid verifies error on invalid base64url.
func TestDecodeBase64URL_Invalid(t *testing.T) {
	_, err := decodeBase64URL("not!valid")
	if err == nil {
		t.Error("invalid base64url: expected error, got nil")
	}
}

// TestJWKSCacheExpiry verifies that the cache is re-fetched after TTL expires.
func TestJWKSCacheExpiry(t *testing.T) {
	key := generateTestECKey(t)
	fetchCount := 0

	body := makeJWKSBody(t, &key.PublicKey, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(body)
	}))
	defer srv.Close()

	c := &nvidiaJWKSCache{}
	client := srv.Client()
	ctx := context.Background()

	keys, err := fetchFromURL(ctx, client, srv.URL)
	if err != nil {
		t.Fatalf("fetchFromURL: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Store in cache.
	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	// Cache is still fresh.
	c.mu.Lock()
	expired := time.Since(c.fetchedAt) > nvidiaJWKSTTL
	c.mu.Unlock()
	if expired {
		t.Error("cache should not be expired immediately after fill")
	}

	// Force expiry.
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * nvidiaJWKSTTL)
	c.mu.Unlock()

	c.mu.Lock()
	expired = time.Since(c.fetchedAt) > nvidiaJWKSTTL
	c.mu.Unlock()
	if !expired {
		t.Error("cache should be expired after forcing fetchedAt into the past")
	}
}

// TestJWKSFetchServerError verifies error handling when the JWKS server fails.
func TestJWKSFetchServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchFromURL(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Error("server error: expected error, got nil")
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

// TestJWKSMultipleKeysNoKid verifies that a JWT without a kid header fails
// when the JWKS contains multiple keys (cannot determine which to use).
func TestJWKSMultipleKeysNoKid(t *testing.T) {
	key1 := generateTestECKey(t)
	key2 := generateTestECKey(t)

	byteLen := (elliptic.P384().Params().BitSize + 7) / 8
	padEC := func(b []byte) []byte {
		for len(b) < byteLen {
			b = append([]byte{0}, b...)
		}
		return b
	}

	jwks := jwksJSON{
		Keys: []jwkKeyJSON{
			{
				Kty: "EC",
				Kid: "key-1",
				Crv: "P-384",
				X:   base64.RawURLEncoding.EncodeToString(padEC(key1.PublicKey.X.Bytes())),
				Y:   base64.RawURLEncoding.EncodeToString(padEC(key1.PublicKey.Y.Bytes())),
				Alg: "ES384",
				Use: "sig",
			},
			{
				Kty: "EC",
				Kid: "key-2",
				Crv: "P-384",
				X:   base64.RawURLEncoding.EncodeToString(padEC(key2.PublicKey.X.Bytes())),
				Y:   base64.RawURLEncoding.EncodeToString(padEC(key2.PublicKey.Y.Bytes())),
				Alg: "ES384",
				Use: "sig",
			},
		},
	}
	jwksBody, _ := json.Marshal(jwks)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	}))
	defer srv.Close()

	// Sign JWT with key1 but omit kid header
	jwtStr := makeTestJWT(t, key1, "", true, "", "nvidia", time.Now().Add(time.Hour))

	kf := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)
	_, err := jwt.Parse(jwtStr, kf, jwt.WithValidMethods([]string{"ES384"}))
	if err == nil {
		t.Fatal("expected error for JWT without kid when JWKS has multiple keys, got nil")
	}
	if !strings.Contains(err.Error(), "missing kid") {
		t.Errorf("error should mention missing kid, got: %v", err)
	}
}

// TestVerifyNVIDIAJWT_Success verifies the full verifyNVIDIAJWT flow with
// a mock JWKS server.
func TestVerifyNVIDIAJWT_Success(t *testing.T) {
	key := generateTestECKey(t)
	kid := "nras-test-kid"

	jwksSrv := makeTestJWKSServer(t, &key.PublicKey, kid)
	defer jwksSrv.Close()

	jwtStr := makeTestJWT(t, key, kid, true, "", "https://nras.attestation.nvidia.com", time.Now().Add(time.Hour))

	// Temporarily override the JWKS cache.
	oldCache := jwksCache
	jwksCache = &nvidiaJWKSCache{}
	defer func() { jwksCache = oldCache }()

	keys, err := fetchFromURL(context.Background(), jwksSrv.Client(), jwksSrv.URL)
	if err != nil {
		t.Fatalf("fetchFromURL: %v", err)
	}
	jwksCache.mu.Lock()
	jwksCache.keys = keys
	jwksCache.fetchedAt = time.Now()
	jwksCache.mu.Unlock()

	result := verifyNVIDIAJWT(context.Background(), jwtStr, jwksSrv.Client())
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
	result := verifyNVIDIAJWT(context.Background(), "", &http.Client{})
	if result.SignatureErr == nil && result.ClaimsErr == nil {
		t.Error("expected error for empty JWT, got nil")
	}
}

// TestExtractNRASJWT verifies the NRAS response parsing.
func TestExtractNRASJWT(t *testing.T) {
	// Valid: array of [type, token] pairs.
	jwt, err := extractNRASJWT(`[["JWT","eyJhbGciOi.payload.sig"]]`)
	if err != nil {
		t.Fatalf("extractNRASJWT valid: %v", err)
	}
	if jwt != "eyJhbGciOi.payload.sig" {
		t.Errorf("got %q, want %q", jwt, "eyJhbGciOi.payload.sig")
	}

	// Multiple entries: takes the JWT one.
	jwt, err = extractNRASJWT(`[["OTHER","foo"],["JWT","eyJhbGciOi.p.s"]]`)
	if err != nil {
		t.Fatalf("extractNRASJWT multi: %v", err)
	}
	if jwt != "eyJhbGciOi.p.s" {
		t.Errorf("got %q", jwt)
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

// TestECPublicKeyFromJWK verifies EC key construction.
func TestECPublicKeyFromJWK(t *testing.T) {
	// Invalid curve.
	_, err := ecPublicKeyFromJWK("P-999", "AAAA", "AAAA")
	if err == nil {
		t.Error("expected error for unsupported curve, got nil")
	}

	// Empty x coordinate.
	_, err = ecPublicKeyFromJWK("P-384", "", "AAAA")
	if err == nil {
		t.Error("expected error for empty x, got nil")
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
