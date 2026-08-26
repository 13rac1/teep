package venice

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// This file verifies the two mechanisms that connect the ACI/1 workload
// keyset to the gateway's TDX quote:
//
//  1. Keyset digest: workload_keyset_digest = "sha256:" + hex(sha256(JCS
//     (workload_keyset))), recomputed from the parsed keyset. The digest is
//     self-asserted, so this check alone proves internal consistency, not
//     hardware binding.
//  2. dstack-KMS key custody: each workload key carries a two-signature
//     chain — the app key signs "{purpose}:{compressed kms_public_key}",
//     and the KMS root signs "dstack-kms-issued:" || app_id || compressed
//     app key. Both are 65-byte recoverable secp256k1 signatures over
//     keccak256 of the message; the recovered root must be an accepted
//     dstack-KMS root, and app_id comes from the quote-bound RTMR3 "app-id"
//     event.
//
// The hardware chain is: TDX quote → REPORTDATA binds signing_public_key
// (SEE: ReportDataVerifier) → membership in workload_keyset.e2ee_public_keys
// → custody chain from the accepted KMS root over the same key, with app_id
// measured into the quote's RTMR3 (integrity of that log is the enforced
// gateway_event_log_integrity factor).
//
// SEE: verify_dstack_kms_receipt_custody in
// https://github.com/Dstack-TEE/private-ai-gateway src/aci/verifier/dstack.rs
// — the reference verifier this implementation matches.

// e2eeCustodyPurpose is the KMS derivation purpose for the secp256k1 E2EE
// key — the key teep encrypts requests to. The custody check accepts a chain
// only for this derivation path, not for any key the app happens to hold.
const e2eeCustodyPurpose = "aci.e2ee.v1"

// defaultACIKMSRootAllow lists accepted dstack-KMS root public keys
// (compressed secp256k1, hex) for the Venice ACI/1 gateway.
//
// The value was recovered from the custody signature chains of live
// attestations of two different models on 2026-08-25 and is trust-on-first-
// use. DANGER: an attacker who controls this list controls which KMS —
// and therefore which key-releasing authority — teep accepts for every
// Venice ACI/1 model. Corroborate against the dstack KmsAuth registry
// (Phala publishes the KMS root on-chain) before extending it.
// SEE: docs/attestation_gaps/venice_aci_gateway.md.
var defaultACIKMSRootAllow = []string{
	"0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1",
}

// ---------------------------------------------------------------------------
// Canonical value builders
// ---------------------------------------------------------------------------
//
// These build any-typed trees that the canonical serializer below converts
// to deterministic bytes, matching the ACI/1 JCS (RFC 8785) digest rules,
// including correct integer representation (no float64 precision loss).

func (k *aciKey) toCanonicalValue() map[string]any {
	return map[string]any{
		"key_id":     k.KeyID,
		"algo":       k.Algo,
		"public_key": k.PublicKey,
	}
}

func (t *aciTLSBinding) toCanonicalValue() map[string]any {
	m := map[string]any{"spki_sha256": t.SPKISHA256}
	if t.Domain != "" {
		m["domain"] = t.Domain
	}
	return m
}

// notAfterCanonical parses the not_after JSON number as uint64.
func notAfterCanonical(n string) (uint64, error) {
	// not_after is u64 in the ACI/1 protocol. json.Number preserves the
	// exact serialized string; parse as uint64 to match the Rust reference
	// implementation.
	na, err := strconv.ParseUint(n, 10, 64)
	if err != nil {
		// The JSON value may be a float64-rounded representation of a
		// uint64. This happens when an intermediary (e.g. a JavaScript
		// gateway) re-serializes u64::MAX (18446744073709551615) through
		// float64, producing "18446744073709552000". Recover the original
		// uint64. Only this one exact value is recovered; the keyset digest
		// cross-check still decides whether the canonical bytes match the
		// declared digest.
		f, ferr := strconv.ParseFloat(n, 64)
		if ferr != nil {
			return 0, fmt.Errorf("parse not_after %q: %w", n, err)
		}
		if f == float64(math.MaxUint64) {
			return math.MaxUint64, nil
		}
		return 0, fmt.Errorf("not_after %q exceeds uint64 range", n)
	}
	return na, nil
}

func (ks *aciWorkloadKeyset) toCanonicalValue() (map[string]any, error) {
	na, err := notAfterCanonical(ks.NotAfter.String())
	if err != nil {
		return nil, err
	}

	receiptKeys := make([]any, len(ks.ReceiptSigningKeys))
	for i := range ks.ReceiptSigningKeys {
		receiptKeys[i] = ks.ReceiptSigningKeys[i].toCanonicalValue()
	}
	e2eeKeys := make([]any, len(ks.E2EEPublicKeys))
	for i := range ks.E2EEPublicKeys {
		e2eeKeys[i] = ks.E2EEPublicKeys[i].toCanonicalValue()
	}
	tlsKeys := make([]any, len(ks.TLSPublicKeys))
	for i := range ks.TLSPublicKeys {
		tlsKeys[i] = ks.TLSPublicKeys[i].toCanonicalValue()
	}

	// Subject is nullable: an untyped nil serializes as JSON null.
	var subject any
	if ks.Subject != nil {
		subject = *ks.Subject
	}
	return map[string]any{
		"subject":              subject,
		"not_after":            na,
		"receipt_signing_keys": receiptKeys,
		"e2ee_public_keys":     e2eeKeys,
		"tls_public_keys":      tlsKeys,
	}, nil
}

// ---------------------------------------------------------------------------
// Canonical JSON serializer (RFC 8785 subset for ACI)
// ---------------------------------------------------------------------------
//
// SYNC: canonicalize, writeCanonicalString, and utf16Compare must produce
// byte-identical output to the JCS serializer in the private-ai-gateway
// Rust implementation (https://github.com/Dstack-TEE/private-ai-gateway);
// the keyset digest cross-check fails on any divergence.
//
// Rejects float64 values — ACI/1's canonical value space defines only
// integer numerics (see toCanonicalValue above), so a float64 reaching here
// indicates a builder bug rather than legitimate input.

func canonicalize(v any) ([]byte, error) {
	buf := make([]byte, 0, 256)
	return writeCanonicalValue(buf, v)
}

func writeCanonicalValue(buf []byte, v any) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return append(buf, "null"...), nil
	case bool:
		if val {
			return append(buf, "true"...), nil
		}
		return append(buf, "false"...), nil
	case string:
		return writeCanonicalString(buf, val), nil
	case int:
		return append(buf, strconv.Itoa(val)...), nil
	case int64:
		return append(buf, strconv.FormatInt(val, 10)...), nil
	case uint64:
		return append(buf, strconv.FormatUint(val, 10)...), nil
	case float64:
		return nil, errors.New("float64 not allowed in ACI canonical value space")
	case []any:
		buf = append(buf, '[')
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			var err error
			buf, err = writeCanonicalValue(buf, item)
			if err != nil {
				return nil, err
			}
		}
		return append(buf, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, utf16Compare)
		buf = append(buf, '{')
		for i, key := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = writeCanonicalString(buf, key)
			buf = append(buf, ':')
			var err error
			buf, err = writeCanonicalValue(buf, val[key])
			if err != nil {
				return nil, err
			}
		}
		return append(buf, '}'), nil
	default:
		return nil, fmt.Errorf("unsupported type %T in ACI canonical value", v)
	}
}

// writeCanonicalString implements RFC 8785 §3.2.2.2 string serialization.
func writeCanonicalString(buf []byte, s string) []byte {
	buf = append(buf, '"')
	for _, c := range s {
		switch c {
		case '"':
			buf = append(buf, '\\', '"')
		case '\\':
			buf = append(buf, '\\', '\\')
		case '\b':
			buf = append(buf, '\\', 'b')
		case '\t':
			buf = append(buf, '\\', 't')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\f':
			buf = append(buf, '\\', 'f')
		case '\r':
			buf = append(buf, '\\', 'r')
		default:
			if c < 0x20 {
				buf = append(buf, fmt.Sprintf("\\u%04x", c)...)
			} else {
				buf = append(buf, string(c)...)
			}
		}
	}
	return append(buf, '"')
}

// utf16Compare orders strings by UTF-16 code unit sequence (RFC 8785 §3.2.3).
func utf16Compare(a, b string) int {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] != bu[i] {
			if au[i] < bu[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(au) < len(bu):
		return -1
	case len(au) > len(bu):
		return 1
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Keyset verification
// ---------------------------------------------------------------------------

// jcsSHA256Hex returns "sha256:<hex>" for the canonical serialization of v.
func jcsSHA256Hex(v any) (string, error) {
	canonical, err := canonicalize(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// VerifyACIKeyset performs ACI/1 workload keyset verification using fields
// from a RawAttestation: the keyset digest recompute, the signing-key
// membership check, and the dstack-KMS custody chain for the E2EE key.
// Returns nil for non-ACI/1 formats. app_id is read from the RTMR3 "app-id"
// event in raw.GatewayEventLog; the enforced gateway_event_log_integrity
// factor is what proves that log matches the quote.
func VerifyACIKeyset(raw *attestation.RawAttestation) *attestation.ACIKeysetResult {
	if raw.BackendFormat != attestation.FormatACI1 {
		return nil
	}
	keyset, ok := raw.ACIWorkloadKeyset.(*aciWorkloadKeyset)
	if !ok || keyset == nil {
		return &attestation.ACIKeysetResult{
			Err: errors.New("ACI/1 workload keyset not available"),
		}
	}
	custody, ok := raw.ACIKeyCustody.(*aciKeyCustody)
	if !ok || custody == nil {
		return &attestation.ACIKeysetResult{
			Err: errors.New("ACI/1 key custody not available"),
		}
	}
	return verifyKeyset(
		keyset,
		custody,
		raw.ACIWorkloadKeysetDigest,
		raw.SigningKey,
		appIDFromEventLog(raw.GatewayEventLog),
		defaultACIKMSRootAllow,
	)
}

// appIDFromEventLog returns the payload of the RTMR3 "app-id" event, or nil
// when absent.
func appIDFromEventLog(entries []attestation.EventLogEntry) []byte {
	for i := range entries {
		if entries[i].IMR == 3 && entries[i].Event == "app-id" {
			b, err := hex.DecodeString(entries[i].EventPayload)
			if err != nil {
				return nil
			}
			return b
		}
	}
	return nil
}

// verifyKeyset performs the three ACI/1 keyset checks:
//
//  1. Recompute sha256(JCS(workload_keyset)) and cross-check against the
//     declared workload_keyset_digest.
//  2. Check that signingKeyHex (the top-level signing_public_key, which the
//     gateway quote's REPORTDATA binds and which teep encrypts E2EE traffic
//     to) is a member of workload_keyset.e2ee_public_keys.
//  3. Verify the dstack-KMS custody chain for the e2eeCustodyPurpose entry:
//     the entry's public_key must equal the signing key, the app key
//     recovered from signature_chain[0] over
//     "{purpose}:{compressed kms_public_key}" must be endorsed by
//     signature_chain[1] over "dstack-kms-issued:" || appID || compressed
//     app key, and the recovered root must be in kmsRootAllow.
//
// Check 3 is what connects the keys to an authority outside the response;
// checks 1 and 2 alone prove only that the response is self-consistent
// around the REPORTDATA-bound signing key.
func verifyKeyset(
	keyset *aciWorkloadKeyset,
	custody *aciKeyCustody,
	declaredKeysetDigest string,
	signingKeyHex string,
	appID []byte,
	kmsRootAllow []string,
) *attestation.ACIKeysetResult {
	// Check 1: keyset digest recompute.
	keysetValue, err := keyset.toCanonicalValue()
	if err != nil {
		return &attestation.ACIKeysetResult{Err: fmt.Errorf("build keyset canonical value: %w", err)}
	}
	computedDigest, err := jcsSHA256Hex(keysetValue)
	if err != nil {
		return &attestation.ACIKeysetResult{Err: fmt.Errorf("compute keyset digest: %w", err)}
	}
	keysetDigestMatch := computedDigest == declaredKeysetDigest

	// Check 2: the REPORTDATA-bound signing key is a keyset E2EE key.
	signingKeyInKeyset := keysetContainsE2EEKey(keyset, signingKeyHex)

	// Check 3: dstack-KMS custody chain for the E2EE key.
	custodyDetail, custodyErr := verifyKeyCustody(custody, signingKeyHex, appID, kmsRootAllow)

	result := &attestation.ACIKeysetResult{
		KeysetDigestMatch:  keysetDigestMatch,
		SigningKeyInKeyset: signingKeyInKeyset,
		CustodyChainValid:  custodyErr == nil,
	}

	var parts []string
	if keysetDigestMatch {
		parts = append(parts, "keyset digest matches")
	} else {
		parts = append(parts, fmt.Sprintf("keyset digest mismatch: computed %s, declared %s", computedDigest, declaredKeysetDigest))
	}
	if signingKeyInKeyset {
		parts = append(parts, "signing key is a keyset e2ee key")
	} else {
		parts = append(parts, "signing key is not in the keyset e2ee_public_keys")
	}
	if custodyErr == nil {
		parts = append(parts, custodyDetail)
	} else {
		parts = append(parts, fmt.Sprintf("key custody: %v", custodyErr))
	}
	result.Detail = strings.Join(parts, "; ")
	return result
}

// keysetContainsE2EEKey reports whether signingKeyHex decodes to the same
// bytes as one of the keyset e2ee_public_keys. An entry that does not decode
// as hex cannot match; an empty or undecodable signing key matches nothing,
// so the caller's factor fails closed.
func keysetContainsE2EEKey(keyset *aciWorkloadKeyset, signingKeyHex string) bool {
	signingKey, err := hex.DecodeString(signingKeyHex)
	if err != nil || len(signingKey) == 0 {
		return false
	}
	for i := range keyset.E2EEPublicKeys {
		endorsed, err := hex.DecodeString(keyset.E2EEPublicKeys[i].PublicKey)
		if err != nil || len(endorsed) != len(signingKey) {
			continue
		}
		if subtle.ConstantTimeCompare(endorsed, signingKey) == 1 {
			return true
		}
	}
	return false
}

// verifyKeyCustody verifies the dstack-KMS custody chain for the E2EE key
// entry (purpose e2eeCustodyPurpose) and returns a detail string on success.
// SEE: the file comment for the chain definition and the reference
// implementation.
func verifyKeyCustody(custody *aciKeyCustody, signingKeyHex string, appID []byte, kmsRootAllow []string) (string, error) {
	if custody.Provider != "dstack-kms" {
		return "", fmt.Errorf("unsupported key custody provider %q", custody.Provider)
	}
	if len(appID) == 0 {
		return "", errors.New("no app-id event in the gateway event log")
	}
	entry, err := custodyEntryForPurpose(custody, e2eeCustodyPurpose)
	if err != nil {
		return "", err
	}
	if err := custodyKeyMatchesSigningKey(entry, signingKeyHex); err != nil {
		return "", err
	}
	if len(entry.SignatureChain) != 2 {
		return "", fmt.Errorf("signature_chain must contain 2 signatures, got %d", len(entry.SignatureChain))
	}

	kmsPubCompressed, err := compressedK256Hex(entry.KMSPublicKey)
	if err != nil {
		return "", fmt.Errorf("kms_public_key: %w", err)
	}
	purposeSig, err := hex.DecodeString(entry.SignatureChain[0])
	if err != nil {
		return "", fmt.Errorf("decode signature_chain[0]: %w", err)
	}
	appKey, err := recoverK256([]byte(entry.Purpose+":"+kmsPubCompressed), purposeSig)
	if err != nil {
		return "", fmt.Errorf("recover app key from purpose signature: %w", err)
	}

	rootSig, err := hex.DecodeString(entry.SignatureChain[1])
	if err != nil {
		return "", fmt.Errorf("decode signature_chain[1]: %w", err)
	}
	rootMessage := append([]byte("dstack-kms-issued:"), appID...)
	rootMessage = append(rootMessage, appKey.SerializeCompressed()...)
	rootKey, err := recoverK256(rootMessage, rootSig)
	if err != nil {
		return "", fmt.Errorf("recover KMS root from app signature: %w", err)
	}

	rootHex := hex.EncodeToString(rootKey.SerializeCompressed())
	if !kmsRootAccepted(rootHex, kmsRootAllow) {
		return "", fmt.Errorf("recovered KMS root %s is not an accepted dstack-KMS root", rootHex)
	}
	return fmt.Sprintf("e2ee key custody chain verified to accepted KMS root (%s...)", rootHex[:16]), nil
}

// custodyEntryForPurpose returns the custody entry whose purpose matches, or
// an error when absent or duplicated.
func custodyEntryForPurpose(custody *aciKeyCustody, purpose string) (*aciCustodyKey, error) {
	var found *aciCustodyKey
	for i := range custody.Keys {
		if custody.Keys[i].Purpose == purpose {
			if found != nil {
				return nil, fmt.Errorf("multiple key custody entries with purpose %q", purpose)
			}
			found = &custody.Keys[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no key custody entry with purpose %q", purpose)
	}
	return found, nil
}

// custodyKeyMatchesSigningKey checks that the custody entry describes the
// REPORTDATA-bound signing key: its public_key equals the signing key, and
// its kms_public_key is the compressed form of the same point.
func custodyKeyMatchesSigningKey(entry *aciCustodyKey, signingKeyHex string) error {
	entryKey, err := hex.DecodeString(entry.PublicKey)
	if err != nil {
		return fmt.Errorf("decode custody public_key: %w", err)
	}
	signingKey, err := hex.DecodeString(signingKeyHex)
	if err != nil || len(signingKey) == 0 {
		return errors.New("signing key is empty or not valid hex")
	}
	if len(entryKey) != len(signingKey) || subtle.ConstantTimeCompare(entryKey, signingKey) != 1 {
		return errors.New("custody e2ee public_key does not match the signing key")
	}
	entryCompressed, err := compressedK256Hex(entry.KMSPublicKey)
	if err != nil {
		return fmt.Errorf("kms_public_key: %w", err)
	}
	signingCompressed, err := compressedK256Hex(signingKeyHex)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(entryCompressed), []byte(signingCompressed)) != 1 {
		return errors.New("custody kms_public_key does not match the signing key")
	}
	return nil
}

// kmsRootAccepted reports whether rootHex is in the allowlist, comparing in
// constant time.
func kmsRootAccepted(rootHex string, allow []string) bool {
	accepted := false
	for _, a := range allow {
		if len(a) == len(rootHex) && subtle.ConstantTimeCompare([]byte(a), []byte(rootHex)) == 1 {
			accepted = true
		}
	}
	return accepted
}

// recoverK256 recovers the secp256k1 public key from a 65-byte r||s||v
// recoverable signature over keccak256(message). The v byte accepts both
// the 0..3 and 27..30 encodings.
func recoverK256(message, sig []byte) (*secp256k1.PublicKey, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("recoverable signature must be 65 bytes, got %d", len(sig))
	}
	v := sig[64]
	if v < 27 {
		v += 27
	}
	// ecdsa.RecoverCompact expects the recovery byte first.
	compact := make([]byte, 0, 65)
	compact = append(compact, v)
	compact = append(compact, sig[:64]...)
	h := sha3.NewLegacyKeccak256()
	h.Write(message)
	pub, _, err := ecdsa.RecoverCompact(compact, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// compressedK256Hex normalizes a hex secp256k1 public key (compressed or
// uncompressed) to its compressed hex form.
func compressedK256Hex(pubHex string) (string, error) {
	b, err := hex.DecodeString(pubHex)
	if err != nil {
		return "", fmt.Errorf("not valid hex: %w", err)
	}
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return "", fmt.Errorf("not a valid secp256k1 public key: %w", err)
	}
	return hex.EncodeToString(pub.SerializeCompressed()), nil
}
