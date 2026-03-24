package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"unicode/utf8"
)

// RekorAPIBase is the base URL for the Rekor transparency log API.
//
//nolint:gochecknoglobals // var instead of const to allow test overrides
var RekorAPIBase = "https://rekor.sigstore.dev"

// Fulcio OIDC extension OID prefix: 1.3.6.1.4.1.57264.1.
var (
	fulcioOIDPrefix  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1}
	oidOIDCIssuer    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidTrigger       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}
	oidSourceCommit  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}
	oidSourceRepo    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}
	oidSourceRef     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}
	oidRunnerEnv     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}
	oidSourceRepoURL = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidRunURL        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}
)

// RekorProvenance holds the build provenance metadata extracted from a Rekor
// transparency log entry's Fulcio certificate.
type RekorProvenance struct {
	Digest         string
	HasCert        bool   // false = raw public key, no Fulcio provenance
	KeyFingerprint string // SHA-256 hex of the PKIX public key bytes
	SubjectURI     string // SAN URI from Fulcio cert (OIDC identity)
	OIDCIssuer     string // 1.3.6.1.4.1.57264.1.1
	Trigger        string // 1.3.6.1.4.1.57264.1.2
	SourceCommit   string // 1.3.6.1.4.1.57264.1.3
	SourceRepo     string // 1.3.6.1.4.1.57264.1.5
	SourceRef      string // 1.3.6.1.4.1.57264.1.6
	SourceRepoURL  string // 1.3.6.1.4.1.57264.1.12
	RunnerEnv      string // 1.3.6.1.4.1.57264.1.11
	RunURL         string // 1.3.6.1.4.1.57264.1.21
	Err            error  // non-fatal: provenance unavailable but digest exists
}

// FetchRekorProvenance queries the Rekor API for a digest's log entry and
// parses Fulcio certificate provenance if present.
//
// All returned UUIDs are tried in order. The function prefers an entry backed
// by a Fulcio certificate (which carries OIDC build-provenance metadata) over
// a raw-public-key entry (F-23: mitigates front-running where an attacker
// inserts a raw-key entry before the legitimate Fulcio-signed entry).
func FetchRekorProvenance(ctx context.Context, digest string, client *http.Client) RekorProvenance {
	uuids, err := fetchRekorUUIDs(ctx, digest, client)
	if err != nil {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("search Rekor: %w", err)}
	}
	if len(uuids) == 0 {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("no Rekor entries for sha256:%s", digest)}
	}

	// Try each UUID; prefer one whose verifier is a Fulcio certificate.
	// This prevents a front-running attack where an adversary inserts a
	// raw-key entry first, causing us to skip build-provenance verification.
	var rawKeyFallback *RekorProvenance
	var lastErr error
	for _, uuid := range uuids {
		body, err := fetchRekorEntry(ctx, uuid, client)
		if err != nil {
			lastErr = fmt.Errorf("fetch Rekor entry %s: %w", uuid, err)
			continue
		}

		verifierPEM, err := extractVerifierPEM(body)
		if err != nil {
			lastErr = fmt.Errorf("extract verifier from %s: %w", uuid, err)
			continue
		}

		block, _ := pem.Decode(verifierPEM)
		if block == nil {
			lastErr = fmt.Errorf("invalid PEM in verifier for %s", uuid)
			continue
		}

		if block.Type == "PUBLIC KEY" {
			// Raw public key — no Fulcio provenance. Keep as fallback and
			// continue looking for an entry with a Fulcio certificate.
			if rawKeyFallback == nil {
				h := sha256.Sum256(block.Bytes)
				p := RekorProvenance{
					Digest:         digest,
					HasCert:        false,
					KeyFingerprint: hex.EncodeToString(h[:]),
				}
				rawKeyFallback = &p
			}
			continue
		}

		if block.Type != "CERTIFICATE" {
			lastErr = fmt.Errorf("unexpected PEM type %q in entry %s", block.Type, uuid)
			continue
		}

		prov, err := parseFulcioProvenance(verifierPEM)
		if err != nil {
			lastErr = fmt.Errorf("parse Fulcio cert in entry %s: %w", uuid, err)
			continue
		}
		prov.Digest = digest

		// Distinguish genuine Fulcio certs (with OIDC issuer) from non-Fulcio
		// X.509 certs that happen to be used for signing. A non-Fulcio cert
		// has no build-provenance OIDs so OIDCIssuer is empty. Treat it like
		// a raw-key fallback and keep looking for a real Fulcio entry.
		if prov.OIDCIssuer == "" {
			if rawKeyFallback == nil {
				p := RekorProvenance{
					Digest:         digest,
					HasCert:        false,
					KeyFingerprint: prov.KeyFingerprint,
				}
				rawKeyFallback = &p
			}
			continue
		}
		return *prov
	}

	// No Fulcio-backed entry found; return raw-key fallback if available.
	if rawKeyFallback != nil {
		return *rawKeyFallback
	}

	if lastErr != nil {
		return RekorProvenance{Digest: digest, Err: lastErr}
	}
	return RekorProvenance{Digest: digest, Err: fmt.Errorf("no usable Rekor entry for sha256:%s", digest)}
}

// fetchRekorUUIDs calls POST /api/v1/index/retrieve to search for log entries
// matching a digest.
func fetchRekorUUIDs(ctx context.Context, digest string, client *http.Client) ([]string, error) {
	payload, err := json.Marshal(map[string]string{"hash": "sha256:" + digest})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, RekorAPIBase+"/api/v1/index/retrieve", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 256))
	}

	var uuids []string
	if err := json.Unmarshal(body, &uuids); err != nil {
		return nil, fmt.Errorf("decode UUIDs: %w", err)
	}
	return uuids, nil
}

// fetchRekorEntry calls POST /api/v1/log/entries/retrieve to fetch a log entry
// by UUID and returns the decoded entry body.
func fetchRekorEntry(ctx context.Context, uuid string, client *http.Client) ([]byte, error) {
	payload, err := json.Marshal(map[string][]string{"entryUUIDs": {uuid}})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, RekorAPIBase+"/api/v1/log/entries/retrieve", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(respBody), 256))
	}

	// Response is an array of maps: [{"<uuid>": {"body": "<base64>", ...}}]
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &entries); err != nil {
		return nil, fmt.Errorf("decode entries array: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("empty entries response")
	}

	// Get the first entry's value (the map has one key: the UUID).
	var entryValue json.RawMessage
	for _, v := range entries[0] {
		entryValue = v
		break
	}

	var entryObj struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(entryValue, &entryObj); err != nil {
		return nil, fmt.Errorf("decode entry object: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(entryObj.Body)
	if err != nil {
		return nil, fmt.Errorf("base64 decode body: %w", err)
	}
	return decoded, nil
}

// extractVerifierPEM extracts the verifier PEM from a decoded Rekor entry body
// (DSSE envelope). The verifier is at spec.signatures[0].verifier and is itself
// base64-encoded.
func extractVerifierPEM(entryBody []byte) ([]byte, error) {
	var entry struct {
		Spec struct {
			Signatures []struct {
				Verifier string `json:"verifier"`
			} `json:"signatures"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(entryBody, &entry); err != nil {
		return nil, fmt.Errorf("decode DSSE entry: %w", err)
	}
	if len(entry.Spec.Signatures) == 0 {
		return nil, errors.New("no signatures in DSSE entry")
	}

	verifierB64 := entry.Spec.Signatures[0].Verifier
	if verifierB64 == "" {
		return nil, errors.New("empty verifier in DSSE signature")
	}

	verifierPEM, err := base64.StdEncoding.DecodeString(verifierB64)
	if err != nil {
		// Some entries have the PEM directly (not base64-wrapped).
		if _, rest := pem.Decode([]byte(verifierB64)); rest != nil {
			return []byte(verifierB64), nil
		}
		return nil, fmt.Errorf("decode verifier base64: %w", err)
	}
	return verifierPEM, nil
}

// parseFulcioProvenance parses a Fulcio certificate PEM and extracts the
// Sigstore OIDC extension OIDs containing build provenance metadata.
func parseFulcioProvenance(certPEM []byte) (*RekorProvenance, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse X.509: %w", err)
	}

	prov := &RekorProvenance{HasCert: true}

	// Extract the OIDC identity from the certificate SAN (URI type).
	if len(cert.URIs) > 0 {
		prov.SubjectURI = cert.URIs[0].String()
	}

	// Compute the public key fingerprint (SHA-256 of SPKI DER bytes).
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	prov.KeyFingerprint = hex.EncodeToString(h[:])

	for _, ext := range cert.Extensions {
		if !hasFulcioPrefix(ext.Id) {
			continue
		}
		val := decodeExtensionValue(ext.Value)

		switch {
		case ext.Id.Equal(oidOIDCIssuer):
			prov.OIDCIssuer = val
		case ext.Id.Equal(oidTrigger):
			prov.Trigger = val
		case ext.Id.Equal(oidSourceCommit):
			prov.SourceCommit = val
		case ext.Id.Equal(oidSourceRepo):
			prov.SourceRepo = val
		case ext.Id.Equal(oidSourceRef):
			prov.SourceRef = val
		case ext.Id.Equal(oidRunnerEnv):
			prov.RunnerEnv = val
		case ext.Id.Equal(oidSourceRepoURL):
			prov.SourceRepoURL = val
		case ext.Id.Equal(oidRunURL):
			prov.RunURL = val
		}
	}

	return prov, nil
}

// hasFulcioPrefix checks whether oid starts with 1.3.6.1.4.1.57264.1.
func hasFulcioPrefix(oid asn1.ObjectIdentifier) bool {
	if len(oid) < len(fulcioOIDPrefix) {
		return false
	}
	for i, v := range fulcioOIDPrefix {
		if oid[i] != v {
			return false
		}
	}
	return true
}

// decodeExtensionValue decodes a Fulcio extension value. These are ASN.1
// UTF8String encoded (tag 0x0C). Some older entries may use raw bytes.
//
// The fallback to raw bytes is logged at Warn level to avoid silently masking
// ASN.1 encoding errors in Rekor entries (F-26).
func decodeExtensionValue(raw []byte) string {
	var s string
	if _, err := asn1.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Fallback: some older Rekor entries store the value as raw UTF-8
	// (pre-ASN.1 encoding convention). Validate it's valid UTF-8 before using.
	if !utf8.Valid(raw) {
		slog.Warn("Rekor extension value is neither valid ASN.1 UTF8String nor valid UTF-8; skipping",
			"oid_hex", hex.EncodeToString(raw))
		return ""
	}
	slog.Debug("Rekor extension: using raw UTF-8 fallback (not ASN.1 encoded)")
	return string(raw)
}

// truncateStr truncates s to maxLen characters, appending "..." if truncated.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
