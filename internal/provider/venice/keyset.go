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
)

// ---------------------------------------------------------------------------
// Canonical value builders
// ---------------------------------------------------------------------------
//
// These build any-typed trees that the canonical serializer below converts
// to deterministic bytes, matching Venice's Rust ACI/1 implementation
// byte-for-byte (JCS/RFC 8785), including correct integer representation
// (no float64 precision loss).

func (k *aciPublicKey) toCanonicalValue() map[string]any {
	return map[string]any{
		"algo":       k.Algo,
		"public_key": k.PublicKey,
	}
}

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

func (id *aciWorkloadIdentity) toCanonicalValue() map[string]any {
	// Convert *string to untyped nil or string value so the canonical
	// serializer emits JSON null (not a typed nil interface).
	var subject any
	if id.Subject != nil {
		subject = *id.Subject
	}
	return map[string]any{
		"public_key": id.PublicKey.toCanonicalValue(),
		"subject":    subject,
	}
}

func (e *aciKeysetEpoch) toCanonicalValue() (map[string]any, error) {
	// NotAfter is u64 in the ACI/1 protocol. json.Number preserves the exact
	// serialized string; parse as uint64 to match the Rust reference
	// implementation.
	na, err := strconv.ParseUint(e.NotAfter.String(), 10, 64)
	if err != nil {
		// The JSON value may be a float64-rounded representation of a uint64.
		// This happens when an intermediary (e.g. a JavaScript gateway)
		// re-serializes u64::MAX (18446744073709551615) through float64,
		// producing "18446744073709552000". Recover the original uint64.
		// Only this one exact value is recovered; the keyset digest
		// cross-check still decides whether the canonical bytes match the
		// endorsed digest.
		f, ferr := strconv.ParseFloat(e.NotAfter.String(), 64)
		if ferr != nil {
			return nil, fmt.Errorf("parse keyset_epoch.not_after %q: %w", e.NotAfter.String(), err)
		}
		if f == float64(math.MaxUint64) {
			na = math.MaxUint64
		} else {
			return nil, fmt.Errorf("keyset_epoch.not_after %q exceeds uint64 range", e.NotAfter.String())
		}
	}
	return map[string]any{
		"version":   e.Version,
		"not_after": na,
	}, nil
}

func (ks *aciWorkloadKeyset) toCanonicalValue() (map[string]any, error) {
	epoch, err := ks.KeysetEpoch.toCanonicalValue()
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

	return map[string]any{
		"workload_identity":    ks.WorkloadIdentity.toCanonicalValue(),
		"keyset_epoch":         epoch,
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
// byte-identical output to the JCS serializer in Venice's private-ai-gateway
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
// Keyset endorsement verification
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

// VerifyACIKeyset performs ACI/1 keyset endorsement verification using fields
// from a RawAttestation. Returns nil for non-ACI/1 formats. The endorsement
// signature is verified using the identity key (workload_identity.public_key),
// not the top-level signing_public_key; the signing key is instead checked
// for membership in the endorsed e2ee_public_keys, which is what connects
// the endorsed keyset to the TDX quote (REPORTDATA binds the signing key).
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
	return verifyKeysetEndorsement(
		keyset,
		raw.ACIWorkloadKeysetDigest,
		raw.ACIWorkloadID,
		raw.ACIKeysetEndorsementSig,
		raw.ACIIdentityKeyHex,
		raw.SigningKey,
	)
}

// verifyKeysetEndorsement performs ACI/1 keyset endorsement verification:
//
//  1. Build canonical value from parsed workload_keyset struct → canonicalize
//     → SHA256 → "sha256:<hex>" → cross-check against declared
//     workload_keyset_digest.
//  2. Build endorsement payload:
//     {"purpose":"aci.keyset.endorsement.v1","workload_keyset_digest":"<computed>"}
//     → canonicalize → payload_bytes.
//  3. ECDSA secp256k1: verify signature over SHA256(payload_bytes)
//     using the identity key.
//  4. Build canonical value from identity public key → canonicalize → SHA256
//     → "sha256:<hex>" → cross-check against declared workload_id.
//  5. Check that signingKeyHex (the top-level signing_public_key, which the
//     TDX quote's REPORTDATA binds and which teep encrypts E2EE traffic to)
//     is a member of the endorsed e2ee_public_keys.
//
// Step 5 is what connects the endorsement to hardware: the identity key
// itself appears only inside the JSON response, so without the membership
// check steps 1-4 prove only that the response is self-consistent. With it,
// the chain is: TDX quote → REPORTDATA → signing_public_key → member of
// endorsed e2ee_public_keys → keyset digest endorsed by identity key →
// workload_id = sha256(canonical identity key).
func verifyKeysetEndorsement(
	keyset *aciWorkloadKeyset,
	declaredKeysetDigest string,
	declaredWorkloadID string,
	endorsementSigHex string,
	identityKeyHex string,
	signingKeyHex string,
) *attestation.ACIKeysetResult {
	if endorsementSigHex == "" {
		return &attestation.ACIKeysetResult{Err: errors.New("keyset_endorsement signature is empty")}
	}
	if identityKeyHex == "" {
		return &attestation.ACIKeysetResult{Err: errors.New("identity public key is empty")}
	}

	// Step 1: Build canonical keyset value, compute digest, cross-check.
	keysetValue, err := keyset.toCanonicalValue()
	if err != nil {
		return &attestation.ACIKeysetResult{Err: fmt.Errorf("build keyset canonical value: %w", err)}
	}
	computedDigest, err := jcsSHA256Hex(keysetValue)
	if err != nil {
		return &attestation.ACIKeysetResult{Err: fmt.Errorf("compute keyset digest: %w", err)}
	}
	keysetDigestMatch := computedDigest == declaredKeysetDigest

	// Step 2: Build endorsement payload and canonicalize.
	payload := map[string]any{
		"purpose":                "aci.keyset.endorsement.v1",
		"workload_keyset_digest": computedDigest,
	}
	payloadCanonical, err := canonicalize(payload)
	if err != nil {
		return &attestation.ACIKeysetResult{Err: fmt.Errorf("canonicalize endorsement payload: %w", err)}
	}

	// Step 3: Verify ECDSA secp256k1 signature.
	sigBytes, err := hex.DecodeString(endorsementSigHex)
	if err != nil {
		return &attestation.ACIKeysetResult{Err: fmt.Errorf("decode endorsement signature hex: %w", err)}
	}
	endorsementValid, err := verifySecp256k1(payloadCanonical, sigBytes, identityKeyHex)
	if err != nil {
		return &attestation.ACIKeysetResult{
			KeysetDigestMatch: keysetDigestMatch,
			Err:               fmt.Errorf("secp256k1 verify: %w", err),
		}
	}

	// Step 4: Compute workload_id from identity key and cross-check.
	identityValue := keyset.WorkloadIdentity.PublicKey.toCanonicalValue()
	computedID, err := jcsSHA256Hex(identityValue)
	if err != nil {
		return &attestation.ACIKeysetResult{
			KeysetDigestMatch: keysetDigestMatch,
			EndorsementValid:  endorsementValid,
			Err:               fmt.Errorf("compute workload_id: %w", err),
		}
	}
	workloadIDMatch := computedID == declaredWorkloadID

	// Step 5: Check the REPORTDATA-bound signing key is an endorsed E2EE key.
	signingKeyInKeyset := keysetContainsE2EEKey(keyset, signingKeyHex)

	result := &attestation.ACIKeysetResult{
		KeysetDigestMatch:  keysetDigestMatch,
		WorkloadIDMatch:    workloadIDMatch,
		EndorsementValid:   endorsementValid,
		SigningKeyInKeyset: signingKeyInKeyset,
	}

	var parts []string
	if endorsementValid {
		parts = append(parts, "endorsement signature valid")
	} else {
		parts = append(parts, "endorsement signature did not verify")
	}
	if keysetDigestMatch {
		parts = append(parts, "keyset digest matches")
	} else {
		parts = append(parts, fmt.Sprintf("keyset digest mismatch: computed %s, declared %s", computedDigest, declaredKeysetDigest))
	}
	if workloadIDMatch {
		parts = append(parts, "workload_id matches")
	} else {
		parts = append(parts, fmt.Sprintf("workload_id mismatch: computed %s, declared %s", computedID, declaredWorkloadID))
	}
	if signingKeyInKeyset {
		parts = append(parts, "signing key is an endorsed e2ee key")
	} else {
		parts = append(parts, "signing key is not in the endorsed e2ee_public_keys")
	}
	result.Detail = strings.Join(parts, "; ")
	return result
}

// keysetContainsE2EEKey reports whether signingKeyHex decodes to the same
// bytes as one of the endorsed e2ee_public_keys. An entry that does not
// decode as hex cannot match; an empty or undecodable signing key matches
// nothing, so the caller's factor fails closed.
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

// verifySecp256k1 verifies a 64-byte r||s ECDSA secp256k1 signature over
// SHA256(message) using the given uncompressed public key (hex).
func verifySecp256k1(message, sig []byte, pubKeyHex string) (bool, error) {
	if len(sig) != 64 {
		return false, fmt.Errorf("signature must be 64 bytes (r||s), got %d", len(sig))
	}
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("decode public key hex: %w", err)
	}
	pubKey, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return false, fmt.Errorf("parse secp256k1 public key: %w", err)
	}
	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(sig[:32]); overflow {
		return false, errors.New("signature r component overflows scalar field")
	}
	if overflow := s.SetByteSlice(sig[32:]); overflow {
		return false, errors.New("signature s component overflows scalar field")
	}
	ecdsaSig := ecdsa.NewSignature(&r, &s)
	hash := sha256.Sum256(message)
	return ecdsaSig.Verify(hash[:], pubKey), nil
}
