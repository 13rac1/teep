package tinfoil

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
)

const attestationPath = "/.well-known/tinfoil-attestation"

var signatureSearchPrefix = []byte(`"signature":"`)

// Attester fetches attestation data from the Tinfoil attestation endpoint.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a Tinfoil Attester configured with the given base URL
// and API key.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	client := config.NewAttestationClient(len(offline) > 0 && offline[0])
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  client,
	}
}

// SetClient replaces the HTTP client used for attestation fetches.
func (a *Attester) SetClient(c *http.Client) { a.client = c }

// FetchAttestation fetches a V3 attestation document from the static base URL.
func (a *Attester) FetchAttestation(ctx context.Context, _ string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	return fetchAndVerifyAttestation(ctx, a.client, a.baseURL, a.apiKey, nonce)
}

// DirectAttester fetches attestation from per-model inference enclaves,
// resolving each model to its dedicated domain via the DirectResolver.
type DirectAttester struct {
	resolver *DirectResolver
	apiKey   string
	client   *http.Client
}

// NewDirectAttester returns an attester that resolves per-model domains via
// the DirectResolver and fetches attestation from the resolved enclave.
func NewDirectAttester(resolver *DirectResolver, apiKey string, offline ...bool) *DirectAttester {
	return &DirectAttester{
		resolver: resolver,
		apiKey:   apiKey,
		client:   config.NewAttestationClient(len(offline) > 0 && offline[0]),
	}
}

// SetClient replaces the HTTP client used for attestation fetches and
// propagates it to the resolver for model discovery.
func (a *DirectAttester) SetClient(c *http.Client) {
	a.client = c
	a.resolver.SetClient(c)
}

// FetchAttestation resolves the model to a per-model domain and fetches
// attestation from that enclave's well-known endpoint. When a
// prompt_cache_key is present in the context, the resolver uses
// hash-based sticky routing for cache-aware backend selection.
func (a *DirectAttester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	m, err := a.resolver.ResolveMapping(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("tinfoil direct: resolve model %q: %w", model, err)
	}
	promptCacheKey := PromptCacheKeyFromContext(ctx)
	domain := m.SelectDomain(promptCacheKey)
	baseURL := "https://" + domain
	slog.DebugContext(ctx, "tinfoil direct: resolved model domain", "model", model, "domain", domain, "repo", m.Repo)
	raw, err := fetchAndVerifyAttestation(ctx, a.client, baseURL, a.apiKey, nonce)
	if err != nil {
		return nil, err
	}
	raw.TinfoilRepo = m.Repo
	return raw, nil
}

// fetchAndVerifyAttestation fetches a V3 attestation document from the given
// base URL, parses it, verifies the nonce and envelope signature.
func fetchAndVerifyAttestation(ctx context.Context, client *http.Client, baseURL, apiKey string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	u, err := url.Parse(baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: parse attestation URL: %w", err)
	}
	q := u.Query()
	q.Set("nonce", nonce.Hex())
	u.RawQuery = q.Encode()

	// Log host+path only; the query string carries the client nonce and must
	// not be written to logs (matches tlsct.WrapLogging nonce-safety policy).
	slog.DebugContext(ctx, "tinfoil: fetching attestation", "host", u.Host, "path", u.Path)
	body, peerSPKI, err := provider.FetchAttestationWithTLS(ctx, client, u.String(), apiKey, maxBodySize)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: fetch attestation: %w", err)
	}

	raw, resp, err := parseV3Response(body)
	if err != nil {
		return nil, err
	}

	// Verify nonce matches (constant-time, decoded bytes per spec).
	responseNonce, err := hex.DecodeString(raw.Nonce)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: decode response nonce hex: %w", err)
	}
	if subtle.ConstantTimeCompare(responseNonce, nonce[:]) != 1 {
		return nil, fmt.Errorf("tinfoil: nonce mismatch: response nonce %q does not match client nonce",
			attestation.NoncePrefix(raw.Nonce))
	}

	// Envelope signature verification.
	if err := verifyEnvelopeSignature(body, resp); err != nil {
		return nil, err
	}

	// TLS channel binding: verify the live TLS peer certificate matches the
	// attested tls_key_fp. The attested tls_key_fp MUST be present — an
	// attestation without TLS binding is malformed and must fail closed.
	if resp.ReportData.TLSKeyFP == "" {
		return nil, errors.New("tinfoil: attestation report_data is missing tls_key_fp; cannot verify TLS channel binding")
	}
	if peerSPKI == "" {
		return nil, errors.New("tinfoil: TLS channel binding failed: no TLS peer state (plain HTTP is not allowed for attestation endpoints)")
	}
	if subtle.ConstantTimeCompare([]byte(peerSPKI), []byte(resp.ReportData.TLSKeyFP)) != 1 {
		return nil, fmt.Errorf("tinfoil: TLS channel binding failed: live peer SPKI %s != attested tls_key_fp %s",
			provider.Truncate(peerSPKI, 16), provider.Truncate(resp.ReportData.TLSKeyFP, 16))
	}

	return raw, nil
}

// verifyEnvelopeSignature verifies the ECDSA envelope signature over the V3 document.
// It extracts the leaf certificate, checks that its public key fingerprint matches
// report_data.tls_key_fp, computes SHA-256 of the JSON with signature replaced by
// empty string, and verifies the DER-encoded ECDSA signature.
func verifyEnvelopeSignature(rawBody []byte, resp *v3Response) error {
	// Parse leaf certificate from PEM.
	block, _ := pem.Decode([]byte(resp.Certificate))
	if block == nil {
		return errors.New("tinfoil: no PEM block in certificate field")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("tinfoil: parse certificate: %w", err)
	}

	// Verify leaf public key is ECDSA.
	ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("tinfoil: certificate public key is %T, want *ecdsa.PublicKey", cert.PublicKey)
	}

	// Verify leaf public key fingerprint matches report_data.tls_key_fp.
	// The fingerprint is SHA-256 of the SPKI (SubjectPublicKeyInfo DER).
	// Use the certificate's already-parsed RawSubjectPublicKeyInfo (the
	// exact DER bytes from the certificate) rather than re-marshaling via
	// x509.MarshalPKIXPublicKey. This avoids a silent error path and matches
	// the "SHA-256 of SPKI DER" definition exactly.
	fpHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fpHex := hex.EncodeToString(fpHash[:])

	if subtle.ConstantTimeCompare([]byte(fpHex), []byte(resp.ReportData.TLSKeyFP)) != 1 {
		return fmt.Errorf("tinfoil: certificate SPKI fingerprint %s does not match report_data.tls_key_fp %s",
			fpHex, resp.ReportData.TLSKeyFP)
	}

	// Compute the hash of the JSON with the signature value replaced by empty string.
	// We do byte-level surgery on the raw JSON to replace the signature value.
	// Trim trailing whitespace — HTTP response bodies may include a trailing
	// newline that was not part of the signed content.
	modifiedBody, err := replaceSignatureValue(bytes.TrimRight(rawBody, "\n\r\t "), resp.Signature)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(modifiedBody)

	// Decode and verify signature.
	sigBytes, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf("tinfoil: base64-decode signature: %w", err)
	}

	if !ecdsa.VerifyASN1(ecdsaKey, hash[:], sigBytes) {
		return errors.New("tinfoil: envelope ECDSA signature verification failed")
	}

	return nil
}

// replaceSignatureValue performs byte-level surgery on the raw JSON to replace
// the signature value with an empty string. It finds "signature":"<value>" and
// replaces it with "signature":"".
func replaceSignatureValue(rawBody []byte, sigValue string) ([]byte, error) {
	// Use LastIndex to ensure we match the top-level "signature" field,
	// not a coincidental occurrence inside a nested string value.
	idx := bytes.LastIndex(rawBody, signatureSearchPrefix)
	if idx < 0 {
		return nil, errors.New("tinfoil: cannot find signature field in raw JSON for envelope verification")
	}

	// The value starts right after the prefix.
	valueStart := idx + len(signatureSearchPrefix)

	// Find the closing quote of the signature value.
	// The base64 value should not contain backslash-escaped quotes.
	valueEnd := bytes.IndexByte(rawBody[valueStart:], '"')
	if valueEnd < 0 {
		return nil, errors.New("tinfoil: cannot find end of signature value in raw JSON")
	}
	valueEnd += valueStart

	// Verify the extracted value matches what we parsed.
	extractedSig := string(rawBody[valueStart:valueEnd])
	if extractedSig != sigValue {
		return nil, errors.New("tinfoil: extracted signature value does not match parsed value")
	}

	// Build modified body: everything before the value + everything after.
	modified := make([]byte, 0, len(rawBody)-(valueEnd-valueStart))
	modified = append(modified, rawBody[:valueStart]...)
	modified = append(modified, rawBody[valueEnd:]...)
	return modified, nil
}
