package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// defaultRekorBase is the production Rekor transparency log API URL.
const defaultRekorBase = "https://rekor.sigstore.dev"

// rekorLogPublicKeyPEM is the production Rekor transparency log's signing key.
// This key signs the Signed Entry Timestamp (SET) and checkpoints.
// Source: https://rekor.sigstore.dev/api/v1/log/publicKey
const rekorLogPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`

// rekorEntry holds the full data returned by the Rekor API for a single log
// entry. The Verification fields are used for SET and inclusion proof checks.
type rekorEntry struct {
	Body           string // base64-encoded entry body
	IntegratedTime int64
	LogID          string
	LogIndex       int64
	Verification   *rekorVerification
}

// rekorVerification holds the cryptographic verification data from a Rekor entry.
type rekorVerification struct {
	SignedEntryTimestamp string // base64-encoded SET
	InclusionProof       *rekorInclusionProof
}

// rekorInclusionProof holds the Merkle tree inclusion proof for a Rekor entry.
type rekorInclusionProof struct {
	Checkpoint string   // signed checkpoint (note format)
	Hashes     []string // hex-encoded sibling hashes
	LogIndex   int64
	RootHash   string // hex-encoded root hash
	TreeSize   int64
}

// RekorClient is an HTTP client for the Rekor transparency log API.
// The base URL is set at construction time and cannot be changed,
// preventing runtime redirection of Rekor lookups.
type RekorClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewRekorClient returns a RekorClient pointing at the production Rekor API.
func NewRekorClient(httpClient *http.Client) *RekorClient {
	return &RekorClient{baseURL: defaultRekorBase, httpClient: httpClient}
}

// NewRekorClientWithBase returns a RekorClient with a custom base URL.
// Intended for tests and environments with a private Rekor instance.
func NewRekorClientWithBase(baseURL string, httpClient *http.Client) *RekorClient {
	return &RekorClient{baseURL: baseURL, httpClient: httpClient}
}

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
	Digest           string
	HasCert          bool   // false = raw public key or non-Fulcio cert
	HasNonFulcioCert bool   // true = X.509 cert present but missing Fulcio OIDC extensions
	KeyFingerprint   string // SHA-256 hex of the PKIX public key bytes
	SubjectURI       string // SAN URI from Fulcio cert (OIDC identity)
	OIDCIssuer       string // 1.3.6.1.4.1.57264.1.1
	Trigger          string // 1.3.6.1.4.1.57264.1.2
	SourceCommit     string // 1.3.6.1.4.1.57264.1.3
	SourceRepo       string // 1.3.6.1.4.1.57264.1.5
	SourceRef        string // 1.3.6.1.4.1.57264.1.6
	SourceRepoURL    string // 1.3.6.1.4.1.57264.1.12
	RunnerEnv        string // 1.3.6.1.4.1.57264.1.11
	RunURL           string // 1.3.6.1.4.1.57264.1.21
	Err              error  // non-fatal: provenance unavailable but digest exists

	// SignatureVerified is true when the DSSE envelope signature was
	// successfully verified against the Fulcio certificate's public key.
	SignatureVerified bool

	// SignatureErr is set when signature verification was attempted but failed.
	SignatureErr error

	// SETVerified is true when the Rekor Signed Entry Timestamp was
	// successfully verified against the Rekor log's public key.
	SETVerified bool

	// SETErr is set when SET verification was attempted but failed.
	SETErr error

	// InclusionVerified is true when the Merkle tree inclusion proof was
	// successfully verified.
	InclusionVerified bool

	// InclusionErr is set when inclusion proof verification was attempted but failed.
	InclusionErr error

	// IntegratedTime is the Unix timestamp when Rekor integrated the entry.
	IntegratedTime int64
}

// FetchRekorProvenance queries the Rekor API for a digest's log entry and
// parses Fulcio certificate provenance if present.
//
// All returned UUIDs are tried in order. The function prefers an entry backed
// by a Fulcio certificate (which carries OIDC build-provenance metadata) over
// a raw-public-key entry (F-23: mitigates front-running where an attacker
// inserts a raw-key entry before the legitimate Fulcio-signed entry).
func (rc *RekorClient) FetchRekorProvenance(ctx context.Context, digest string) RekorProvenance {
	uuids, err := rc.fetchRekorUUIDs(ctx, digest)
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
		entry, err := rc.fetchRekorEntry(ctx, uuid)
		if err != nil {
			lastErr = fmt.Errorf("fetch Rekor entry %s: %w", uuid, err)
			continue
		}

		body, err := base64.StdEncoding.DecodeString(entry.Body)
		if err != nil {
			lastErr = fmt.Errorf("base64 decode body for %s: %w", uuid, err)
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
				verifyRekorEntry(entry, &p)
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
		prov.IntegratedTime = entry.IntegratedTime

		// Distinguish genuine Fulcio certs (with OIDC issuer) from non-Fulcio
		// X.509 certs that happen to be used for signing. A non-Fulcio cert
		// has no build-provenance OIDs so OIDCIssuer is empty. Treat it like
		// a raw-key fallback and keep looking for a real Fulcio entry.
		if prov.OIDCIssuer == "" {
			if rawKeyFallback == nil {
				p := RekorProvenance{
					Digest:           digest,
					HasCert:          false,
					HasNonFulcioCert: true,
					KeyFingerprint:   prov.KeyFingerprint,
				}
				verifyRekorEntry(entry, &p)
				rawKeyFallback = &p
			}
			continue
		}
		// Verify the DSSE envelope signature against the Fulcio cert.
		if err := verifyDSSESignature(body, verifierPEM); err != nil {
			prov.SignatureErr = fmt.Errorf("DSSE signature verification: %w", err)
		} else {
			prov.SignatureVerified = true
		}

		// Verify the Signed Entry Timestamp (SET) and inclusion proof.
		verifyRekorEntry(entry, prov)

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
func (rc *RekorClient) fetchRekorUUIDs(ctx context.Context, digest string) ([]string, error) {
	payload, err := json.Marshal(map[string]string{"hash": "sha256:" + digest})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rc.baseURL+"/api/v1/index/retrieve", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(body)))
	}

	var uuids []string
	if err := json.Unmarshal(body, &uuids); err != nil {
		return nil, fmt.Errorf("decode UUIDs: %w", err)
	}
	return uuids, nil
}

// fetchRekorEntry calls POST /api/v1/log/entries/retrieve to fetch a log entry
// by UUID and returns the full entry including verification data.
func (rc *RekorClient) fetchRekorEntry(ctx context.Context, uuid string) (*rekorEntry, error) {
	payload, err := json.Marshal(map[string][]string{"entryUUIDs": {uuid}})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rc.baseURL+"/api/v1/log/entries/retrieve", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(respBody)))
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
		Body           string `json:"body"`
		IntegratedTime *int64 `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       *int64 `json:"logIndex"`
		Verification   *struct {
			SignedEntryTimestamp string `json:"signedEntryTimestamp"`
			InclusionProof       *struct {
				Checkpoint string   `json:"checkpoint"`
				Hashes     []string `json:"hashes"`
				LogIndex   *int64   `json:"logIndex"`
				RootHash   string   `json:"rootHash"`
				TreeSize   *int64   `json:"treeSize"`
			} `json:"inclusionProof"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(entryValue, &entryObj); err != nil {
		return nil, fmt.Errorf("decode entry object: %w", err)
	}

	re := &rekorEntry{
		Body:  entryObj.Body,
		LogID: entryObj.LogID,
	}
	if entryObj.IntegratedTime != nil {
		re.IntegratedTime = *entryObj.IntegratedTime
	}
	if entryObj.LogIndex != nil {
		re.LogIndex = *entryObj.LogIndex
	}
	if entryObj.Verification != nil {
		re.Verification = &rekorVerification{
			SignedEntryTimestamp: entryObj.Verification.SignedEntryTimestamp,
		}
		if ip := entryObj.Verification.InclusionProof; ip != nil {
			rip := &rekorInclusionProof{
				Checkpoint: ip.Checkpoint,
				Hashes:     ip.Hashes,
				RootHash:   ip.RootHash,
			}
			if ip.LogIndex != nil {
				rip.LogIndex = *ip.LogIndex
			}
			if ip.TreeSize != nil {
				rip.TreeSize = *ip.TreeSize
			}
			re.Verification.InclusionProof = rip
		}
	}
	return re, nil
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

// verifyDSSESignature verifies the DSSE envelope signature in a Rekor entry
// body against the provided verifier certificate. The DSSE Pre-Authentication
// Encoding (PAE) is: "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
// where payload is the raw (base64-decoded) content.
func verifyDSSESignature(entryBody, verifierPEM []byte) error {
	var entry struct {
		Kind string `json:"kind"`
		Spec struct {
			Content struct {
				Envelope struct {
					Payload     string `json:"payload"`
					PayloadType string `json:"payloadType"`
					Signatures  []struct {
						Sig string `json:"sig"`
					} `json:"signatures"`
				} `json:"envelope"`
			} `json:"content"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(entryBody, &entry); err != nil {
		return fmt.Errorf("decode entry: %w", err)
	}
	if entry.Kind != "dsse" {
		return fmt.Errorf("signature verification not supported for entry kind %q", entry.Kind)
	}

	env := entry.Spec.Content.Envelope
	if len(env.Signatures) == 0 {
		return errors.New("no signatures in DSSE envelope")
	}

	// Decode the signature.
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Build the PAE (Pre-Authentication Encoding).
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	pae := buildPAE(env.PayloadType, payloadBytes)

	// Parse the verifier certificate.
	block, _ := pem.Decode(verifierPEM)
	if block == nil {
		return errors.New("no PEM block in verifier")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse verifier certificate: %w", err)
	}

	// Verify the signature over the PAE using the cert's public key.
	digest := sha256.Sum256(pae)
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
			return errors.New("ECDSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type %T for DSSE verification", cert.PublicKey)
	}
	return nil
}

// buildPAE constructs the DSSE Pre-Authentication Encoding.
// Format: "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload.
func buildPAE(payloadType string, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("DSSEv1")
	buf.WriteByte(' ')
	fmt.Fprintf(&buf, "%d", len(payloadType))
	buf.WriteByte(' ')
	buf.WriteString(payloadType)
	buf.WriteByte(' ')
	fmt.Fprintf(&buf, "%d", len(payload))
	buf.WriteByte(' ')
	buf.Write(payload)
	return buf.Bytes()
}

// verifyRekorEntry verifies the Signed Entry Timestamp (SET) and Merkle tree
// inclusion proof for a Rekor entry. Results are stored on the provided
// RekorProvenance. Verification failures are non-fatal — the provenance is
// still usable, but the report will reflect the verification status.
func verifyRekorEntry(entry *rekorEntry, prov *RekorProvenance) {
	// SET verification requires the Rekor public key; inclusion proof does not.
	// Verify them independently so a key parse failure doesn't mask a working
	// inclusion proof (or vice versa).
	rekorKey, err := parseRekorPublicKey()
	if err != nil {
		prov.SETErr = fmt.Errorf("parse Rekor public key: %w", err)
	} else {
		if err := verifySET(entry, rekorKey); err != nil {
			prov.SETErr = fmt.Errorf("SET verification: %w", err)
		} else {
			prov.SETVerified = true
		}
	}

	// Verify the Merkle tree inclusion proof independently of SET.
	if err := verifyInclusionProof(entry); err != nil {
		prov.InclusionErr = fmt.Errorf("inclusion proof: %w", err)
	} else {
		prov.InclusionVerified = true
	}
}

// verifySET verifies the Rekor Signed Entry Timestamp (SET). The SET is an
// ECDSA signature over the JSON-canonicalized bundle {body, integratedTime,
// logIndex, logID}. This proves Rekor's log server acknowledged the entry.
func verifySET(entry *rekorEntry, rekorKey *ecdsa.PublicKey) error {
	if entry.Verification == nil || entry.Verification.SignedEntryTimestamp == "" {
		return errors.New("no signed entry timestamp in Rekor response")
	}

	setBytes, err := base64.StdEncoding.DecodeString(entry.Verification.SignedEntryTimestamp)
	if err != nil {
		return fmt.Errorf("decode SET: %w", err)
	}

	// The SET signs over {body, integratedTime, logIndex, logID}.
	// body is the base64-encoded entry body (kept as-is, not decoded).
	type setBundle struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	}
	bundle := setBundle{
		Body:           entry.Body,
		IntegratedTime: entry.IntegratedTime,
		LogIndex:       entry.LogIndex,
		LogID:          entry.LogID,
	}
	contents, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(contents)
	if err != nil {
		return fmt.Errorf("canonicalize bundle: %w", err)
	}

	h := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(rekorKey, h[:], setBytes) {
		return errors.New("SET signature does not match Rekor public key")
	}
	return nil
}

// verifyInclusionProof verifies a Rekor entry's Merkle tree inclusion proof.
// The leaf hash is SHA-256(0x00 || entryBytes) per RFC 6962 §2.1.
// This proves the entry is actually present in the append-only log at the
// claimed position, preventing a MITM from fabricating entries.
func verifyInclusionProof(entry *rekorEntry) error {
	if entry.Verification == nil || entry.Verification.InclusionProof == nil {
		return errors.New("no inclusion proof in Rekor response")
	}

	ip := entry.Verification.InclusionProof

	// Validate bounds before casting int64 → uint64. A malicious or garbled
	// Rekor response could produce negative values that wrap to huge uint64s.
	if ip.LogIndex < 0 {
		return fmt.Errorf("inclusion proof logIndex is negative: %d", ip.LogIndex)
	}
	if ip.TreeSize <= 0 {
		return fmt.Errorf("inclusion proof treeSize is non-positive: %d", ip.TreeSize)
	}
	if ip.LogIndex >= ip.TreeSize {
		return fmt.Errorf("inclusion proof logIndex (%d) >= treeSize (%d)", ip.LogIndex, ip.TreeSize)
	}
	// A Merkle tree of depth D has at most D sibling hashes. For a SHA-256
	// tree, D ≤ 64 covers well beyond any realistic log size (~2^64 entries).
	const maxProofHashes = 64
	if len(ip.Hashes) > maxProofHashes {
		return fmt.Errorf("inclusion proof has %d hashes, exceeds maximum %d", len(ip.Hashes), maxProofHashes)
	}

	entryBytes, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return fmt.Errorf("decode entry body: %w", err)
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(entryBytes)

	rootHash, err := hex.DecodeString(ip.RootHash)
	if err != nil {
		return fmt.Errorf("decode root hash: %w", err)
	}

	var hashes [][]byte
	for _, h := range ip.Hashes {
		hb, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("decode proof hash: %w", err)
		}
		hashes = append(hashes, hb)
	}

	if err := proof.VerifyInclusion(rfc6962.DefaultHasher,
		uint64(ip.LogIndex), uint64(ip.TreeSize), leafHash, hashes, rootHash); err != nil {
		return fmt.Errorf("merkle inclusion proof invalid: %w", err)
	}
	return nil
}

// rekorPublicKeyOverride when non-empty replaces the embedded Rekor
// transparency log public key for SET verification. Tests use this to
// inject a key matching mock-signed entry timestamps.
var rekorPublicKeyOverride string

// SetRekorPublicKeyOverride replaces the embedded Rekor transparency log
// public key for SET verification. Pass an empty string to restore the
// default production key. This exists solely for test mocks.
func SetRekorPublicKeyOverride(pemKey string) {
	rekorPublicKeyOverride = pemKey
}

// parseRekorPublicKey parses the embedded Rekor transparency log public key.
func parseRekorPublicKey() (*ecdsa.PublicKey, error) {
	keyPEM := rekorLogPublicKeyPEM
	if rekorPublicKeyOverride != "" {
		keyPEM = rekorPublicKeyOverride
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("no PEM block in Rekor public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rekor public key is %T, expected *ecdsa.PublicKey", pub)
	}
	return ecKey, nil
}

// truncateStr truncates s to 256 characters, appending "..." if truncated.
func truncateStr(s string) string {
	const maxLen = 256
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
