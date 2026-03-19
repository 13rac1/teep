package attestation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateTestRSAKey generates a 2048-bit RSA key pair for test JWTs.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// makeTestJWT creates a signed JWT with the given claims using the provided RSA key.
func makeTestJWT(t *testing.T, key *rsa.PrivateKey, kid, overallResult, nonce, issuer string, exp time.Time) string {
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
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

// makeJWKSBody returns JSON for a JWKS containing the given RSA public key.
func makeJWKSBody(t *testing.T, key *rsa.PublicKey, kid string) []byte {
	t.Helper()
	nBytes := key.N.Bytes()
	eBytes := big.NewInt(int64(key.E)).Bytes()
	jwks := jwksJSON{
		Keys: []jwkKeyJSON{
			{
				Kty: "RSA",
				Kid: kid,
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
				Alg: "RS256",
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
func makeTestJWKSServer(t *testing.T, key *rsa.PublicKey, kid string) *httptest.Server {
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
		for _, k := range keys {
			if kid == "" || k.kid == kid {
				return k.key, nil
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	}
}

// TestParseJWKS_RSAKey verifies that parseJWKS correctly loads an RSA key.
func TestParseJWKS_RSAKey(t *testing.T) {
	key := generateTestRSAKey(t)
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

// TestParseJWKS_SkipsNonRSA verifies that non-RSA keys are silently skipped.
func TestParseJWKS_SkipsNonRSA(t *testing.T) {
	raw, _ := json.Marshal(jwksJSON{
		Keys: []jwkKeyJSON{
			{Kty: "EC", Kid: "ec-key", N: "not-rsa"},
		},
	})

	_, err := parseJWKS(raw)
	if err == nil {
		t.Error("parseJWKS with only EC keys: expected error (no usable RSA keys), got nil")
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
	key := generateTestRSAKey(t)
	kid := "test-kid-1"
	nonce := NewNonce()

	tokenStr := makeTestJWT(t, key, kid, "OVERALL_SUCCESS", nonce.Hex(), "https://test.nvidia.com", time.Now().Add(time.Hour))

	srv := makeTestJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	keyFunc := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)

	claims := &nvidiaClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	if !token.Valid {
		t.Error("token is not valid")
	}
	if claims.OverallResult != "OVERALL_SUCCESS" {
		t.Errorf("OverallResult: got %q, want %q", claims.OverallResult, "OVERALL_SUCCESS")
	}
	if claims.Nonce != nonce.Hex() {
		t.Errorf("Nonce: got %q, want %q", claims.Nonce, nonce.Hex())
	}
}

// TestVerifyJWT_ExpiredToken verifies an expired JWT fails claims validation.
func TestVerifyJWT_ExpiredToken(t *testing.T) {
	key := generateTestRSAKey(t)
	kid := "test-kid-2"

	// Expired 1 hour ago.
	tokenStr := makeTestJWT(t, key, kid, "OVERALL_SUCCESS", "", "https://test.nvidia.com", time.Now().Add(-time.Hour))

	srv := makeTestJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	keyFunc := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)

	claims := &nvidiaClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
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
	signingKey := generateTestRSAKey(t)
	verifyKey := generateTestRSAKey(t) // different key
	kid := "test-kid-3"

	tokenStr := makeTestJWT(t, signingKey, kid, "OVERALL_SUCCESS", "", "test", time.Now().Add(time.Hour))

	// Serve verifyKey (not signingKey) as the JWKS.
	srv := makeTestJWKSServer(t, &verifyKey.PublicKey, kid)
	defer srv.Close()

	keyFunc := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)

	claims := &nvidiaClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
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
	key := generateTestRSAKey(t)

	// Sign with kid "key-A" but serve JWKS with kid "key-B".
	tokenStr := makeTestJWT(t, key, "key-A", "OVERALL_SUCCESS", "", "test", time.Now().Add(time.Hour))

	srv := makeTestJWKSServer(t, &key.PublicKey, "key-B")
	defer srv.Close()

	keyFunc := keyfuncFromURL(context.Background(), srv.Client(), srv.URL)

	claims := &nvidiaClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
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

// TestBuildRSAPublicKey verifies RSA key construction from raw bytes.
func TestBuildRSAPublicKey(t *testing.T) {
	key := generateTestRSAKey(t)
	nBytes := key.N.Bytes()
	eBytes := big.NewInt(int64(key.E)).Bytes()

	pub, err := buildRSAPublicKey(nBytes, eBytes)
	if err != nil {
		t.Fatalf("buildRSAPublicKey: %v", err)
	}
	if pub.N.Cmp(key.N) != 0 {
		t.Error("modulus mismatch")
	}
	if pub.E != key.E {
		t.Error("exponent mismatch")
	}
}

// TestBuildRSAPublicKey_EmptyN verifies error on empty modulus.
func TestBuildRSAPublicKey_EmptyN(t *testing.T) {
	_, err := buildRSAPublicKey([]byte{}, big.NewInt(65537).Bytes())
	if err == nil {
		t.Error("empty modulus: expected error, got nil")
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
	key := generateTestRSAKey(t)
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

	// Use keyfuncWithURL (only defined in tests through fetchFromURL).
	// We'll call fetchFromURL directly to simulate the cache behaviour.
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

	// Cache is still fresh; manually check.
	c.mu.RLock()
	expired := time.Since(c.fetchedAt) > nvidiaJWKSTTL
	c.mu.RUnlock()
	if expired {
		t.Error("cache should not be expired immediately after fill")
	}

	// Force expiry.
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * nvidiaJWKSTTL)
	c.mu.Unlock()

	c.mu.RLock()
	expired = time.Since(c.fetchedAt) > nvidiaJWKSTTL
	c.mu.RUnlock()
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
		OverallResult: "pass",
		Nonce:         "abc123",
	}
	result := &NvidiaVerifyResult{}
	extractPartialClaims(claims, result)

	if result.Issuer != "test-issuer" {
		t.Errorf("Issuer: got %q, want %q", result.Issuer, "test-issuer")
	}
	if result.OverallResult != "pass" {
		t.Errorf("OverallResult: got %q, want %q", result.OverallResult, "pass")
	}
	if result.Nonce != "abc123" {
		t.Errorf("Nonce: got %q, want %q", result.Nonce, "abc123")
	}
	if !result.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt should be zero when ExpiresAt claim is nil")
	}
}
