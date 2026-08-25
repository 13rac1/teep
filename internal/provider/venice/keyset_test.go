package venice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ---------------------------------------------------------------------------
// Canonical serializer tests
// ---------------------------------------------------------------------------

func TestCanonicalize_Primitives(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want string
	}{
		{"nil", nil, "null"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"string", "hello", `"hello"`},
		{"int_zero", 0, "0"},
		{"int_negative", -42, "-42"},
		{"int64", int64(123), "123"},
		{"uint64", uint64(18446744073709551615), "18446744073709551615"},
		{"uint64_zero", uint64(0), "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalize(tc.v)
			if err != nil {
				t.Fatalf("canonicalize(%v): %v", tc.v, err)
			}
			if string(got) != tc.want {
				t.Errorf("canonicalize(%v) = %q, want %q", tc.v, got, tc.want)
			}
		})
	}
}

func TestCanonicalize_RejectsFloat(t *testing.T) {
	_, err := canonicalize(float64(3.14))
	if err == nil {
		t.Error("expected error for float64 value")
	}
}

func TestCanonicalize_StringEscaping(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"quote", `he said "hi"`, `"he said \"hi\""`},
		{"backslash", `a\b`, `"a\\b"`},
		{"newline", "line1\nline2", `"line1\nline2"`},
		{"tab", "a\tb", `"a\tb"`},
		{"control_char", "a\x01b", `"a\u0001b"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalize(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("canonicalize(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestCanonicalize_KeyOrder(t *testing.T) {
	// Keys should be sorted by UTF-16 code unit sequence.
	m := map[string]any{"z": 1, "a": 2, "m": 3}
	got, err := canonicalize(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"m":3,"z":1}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalize_Array(t *testing.T) {
	got, err := canonicalize([]any{1, "two", nil, true})
	if err != nil {
		t.Fatal(err)
	}
	want := `[1,"two",null,true]`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalize_EmptyArray(t *testing.T) {
	got, err := canonicalize([]any{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "[]" {
		t.Errorf("got %q, want %q", got, "[]")
	}
}

func TestCanonicalize_NestedObject(t *testing.T) {
	m := map[string]any{
		"b": map[string]any{"y": 2, "x": 1},
		"a": "first",
	}
	got, err := canonicalize(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"first","b":{"x":1,"y":2}}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// JCS SHA256 tests
// ---------------------------------------------------------------------------

func TestJcsSHA256Hex_Deterministic(t *testing.T) {
	// Go maps are unordered, so canonicalization must sort keys.
	input := map[string]any{"b": "2", "a": "1"}
	d, err := jcsSHA256Hex(input)
	if err != nil {
		t.Fatal(err)
	}

	// Verify format.
	if d[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix, got %s", d[:7])
	}

	// Verify against known value. Canonical form: {"a":"1","b":"2"}
	h := sha256.Sum256([]byte(`{"a":"1","b":"2"}`))
	expected := "sha256:" + hex.EncodeToString(h[:])
	if d != expected {
		t.Errorf("got %s, want %s", d, expected)
	}
}

func TestJcsSHA256Hex_Uint64Max(t *testing.T) {
	// Verify that uint64 max is correctly serialized as an integer, not float.
	input := map[string]any{"n": uint64(math.MaxUint64)}
	d, err := jcsSHA256Hex(input)
	if err != nil {
		t.Fatal(err)
	}

	// Canonical: {"n":18446744073709551615}
	h := sha256.Sum256([]byte(`{"n":18446744073709551615}`))
	expected := "sha256:" + hex.EncodeToString(h[:])
	if d != expected {
		t.Errorf("got %s, want %s", d, expected)
	}
}

// ---------------------------------------------------------------------------
// Canonical value builder tests
// ---------------------------------------------------------------------------

func TestKeysetEpoch_ToCanonicalValue(t *testing.T) {
	epoch := aciKeysetEpoch{
		Version:  1,
		NotAfter: json.Number("18446744073709551615"),
	}
	cv, err := epoch.toCanonicalValue()
	if err != nil {
		t.Fatal(err)
	}

	got, err := canonicalize(cv)
	if err != nil {
		t.Fatal(err)
	}
	// Keys sorted: not_after before version.
	want := `{"not_after":18446744073709551615,"version":1}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestKeysetEpoch_Float64Rounded(t *testing.T) {
	// Wire JSON from JavaScript gateways has "18446744073709552000" instead
	// of "18446744073709551615" (u64::MAX) due to float64 precision loss.
	// The canonical value builder must recover the original u64::MAX.
	epoch := aciKeysetEpoch{
		Version:  1,
		NotAfter: json.Number("18446744073709552000"),
	}
	cv, err := epoch.toCanonicalValue()
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonicalize(cv)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"not_after":18446744073709551615,"version":1}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestKeysetEpoch_InvalidNotAfter(t *testing.T) {
	epoch := aciKeysetEpoch{
		Version:  1,
		NotAfter: json.Number("not-a-number"),
	}
	_, err := epoch.toCanonicalValue()
	if err == nil {
		t.Error("expected error for invalid not_after")
	}
}

func TestWorkloadKeyset_ToCanonicalValue(t *testing.T) {
	ks := &aciWorkloadKeyset{
		WorkloadIdentity: aciWorkloadIdentity{
			PublicKey: aciPublicKey{
				Algo:      "ecdsa-secp256k1",
				PublicKey: "deadbeef",
			},
			Subject: nil,
		},
		KeysetEpoch: aciKeysetEpoch{
			Version:  1,
			NotAfter: json.Number("18446744073709551615"),
		},
		ReceiptSigningKeys: []aciKey{},
		E2EEPublicKeys:     []aciKey{},
		TLSPublicKeys:      []aciTLSBinding{},
	}

	cv, err := ks.toCanonicalValue()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the canonical value serializes without error.
	got, err := canonicalize(cv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("canonical keyset: %s", got)

	// Verify the digest is stable.
	d, err := jcsSHA256Hex(cv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("keyset digest: %s", d)

	// Compute expected digest from known canonical form.
	// Canonical key ordering:
	//   e2ee_public_keys < keyset_epoch < receipt_signing_keys < tls_public_keys < workload_identity
	// Inner objects also sorted by key.
	canonical := `{"e2ee_public_keys":[],"keyset_epoch":{"not_after":18446744073709551615,"version":1},"receipt_signing_keys":[],"tls_public_keys":[],"workload_identity":{"public_key":{"algo":"ecdsa-secp256k1","public_key":"deadbeef"},"subject":null}}`
	h := sha256.Sum256([]byte(canonical))
	expected := "sha256:" + hex.EncodeToString(h[:])
	if d != expected {
		t.Errorf("keyset digest mismatch:\n  got:  %s\n  want: %s\n  canonical: %s", d, expected, got)
	}
}

func TestPublicKey_WorkloadID(t *testing.T) {
	pk := aciPublicKey{
		Algo:      "ecdsa-secp256k1",
		PublicKey: "deadbeef",
	}
	d, err := jcsSHA256Hex(pk.toCanonicalValue())
	if err != nil {
		t.Fatal(err)
	}

	// Canonical: {"algo":"ecdsa-secp256k1","public_key":"deadbeef"}
	h := sha256.Sum256([]byte(`{"algo":"ecdsa-secp256k1","public_key":"deadbeef"}`))
	expected := "sha256:" + hex.EncodeToString(h[:])
	if d != expected {
		t.Errorf("workload_id mismatch: got %s, want %s", d, expected)
	}
}

// ---------------------------------------------------------------------------
// VerifyACIKeyset / verifyKeysetEndorsement tests
// ---------------------------------------------------------------------------

// signEndorsement builds the ACI/1 endorsement payload for keysetDigest and
// signs it with priv, returning the 64-byte r||s hex signature that
// verifyKeysetEndorsement expects.
func signEndorsement(t *testing.T, priv *secp256k1.PrivateKey, keysetDigest string) string {
	t.Helper()
	payload := map[string]any{
		"purpose":                "aci.keyset.endorsement.v1",
		"workload_keyset_digest": keysetDigest,
	}
	payloadCanonical, err := canonicalize(payload)
	if err != nil {
		t.Fatalf("canonicalize endorsement payload: %v", err)
	}
	hash := sha256.Sum256(payloadCanonical)
	sig := ecdsa.Sign(priv, hash[:])
	r, s := sig.R(), sig.S()
	rBytes, sBytes := r.Bytes(), s.Bytes()
	return hex.EncodeToString(append(rBytes[:], sBytes[:]...))
}

// TestVerifyKeysetEndorsement_HappyPath: generate a real secp256k1 keypair,
// build a workload keyset whose identity key is that keypair's public key and
// whose e2ee_public_keys contain the signing key, sign the JCS-canonicalized
// endorsement payload with the private key, and confirm
// verifyKeysetEndorsement (via verifySecp256k1) reports EndorsementValid,
// KeysetDigestMatch, WorkloadIDMatch, and SigningKeyInKeyset all true. Every
// other keyset_test.go case up to this point only exercises error paths or
// pure-canonicalization helpers — none produces and verifies a valid
// signature end-to-end.
func TestVerifyKeysetEndorsement_HappyPath(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	identityKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())
	const signingKeyHex = "04eeff"

	keyset := &aciWorkloadKeyset{
		WorkloadIdentity: aciWorkloadIdentity{
			PublicKey: aciPublicKey{Algo: "ecdsa-secp256k1", PublicKey: identityKeyHex},
		},
		KeysetEpoch:        aciKeysetEpoch{Version: 1, NotAfter: json.Number("18446744073709551615")},
		ReceiptSigningKeys: []aciKey{{KeyID: "receipt-v1", Algo: "ecdsa-secp256k1", PublicKey: "04ccdd"}},
		E2EEPublicKeys:     []aciKey{{KeyID: "e2ee-v1", Algo: "secp256k1-aes-256-gcm", PublicKey: signingKeyHex}},
		TLSPublicKeys:      []aciTLSBinding{{Domain: "test.example.com", SPKISHA256: "aabbccdd"}},
	}

	keysetValue, err := keyset.toCanonicalValue()
	if err != nil {
		t.Fatalf("toCanonicalValue: %v", err)
	}
	keysetDigest, err := jcsSHA256Hex(keysetValue)
	if err != nil {
		t.Fatalf("jcsSHA256Hex(keyset): %v", err)
	}
	workloadID, err := jcsSHA256Hex(keyset.WorkloadIdentity.PublicKey.toCanonicalValue())
	if err != nil {
		t.Fatalf("jcsSHA256Hex(identity): %v", err)
	}
	sigHex := signEndorsement(t, priv, keysetDigest)

	result := verifyKeysetEndorsement(keyset, keysetDigest, workloadID, sigHex, identityKeyHex, signingKeyHex)
	if result.Err != nil {
		t.Fatalf("verifyKeysetEndorsement: unexpected error: %v (detail: %s)", result.Err, result.Detail)
	}
	if !result.EndorsementValid {
		t.Errorf("EndorsementValid = false, want true: %s", result.Detail)
	}
	if !result.KeysetDigestMatch {
		t.Errorf("KeysetDigestMatch = false, want true: %s", result.Detail)
	}
	if !result.WorkloadIDMatch {
		t.Errorf("WorkloadIDMatch = false, want true: %s", result.Detail)
	}
	if !result.SigningKeyInKeyset {
		t.Errorf("SigningKeyInKeyset = false, want true: %s", result.Detail)
	}
}

// TestVerifyKeysetEndorsement_SigningKeyNotInKeyset: a valid endorsement over
// a keyset that does not contain the REPORTDATA-bound signing key must report
// SigningKeyInKeyset false — the endorsement is self-consistent but unbound
// to the hardware quote, and the factor fails.
func TestVerifyKeysetEndorsement_SigningKeyNotInKeyset(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	identityKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())

	keyset := &aciWorkloadKeyset{
		WorkloadIdentity: aciWorkloadIdentity{
			PublicKey: aciPublicKey{Algo: "ecdsa-secp256k1", PublicKey: identityKeyHex},
		},
		KeysetEpoch:    aciKeysetEpoch{Version: 1, NotAfter: json.Number("100")},
		E2EEPublicKeys: []aciKey{{KeyID: "e2ee-v1", Algo: "secp256k1-aes-256-gcm", PublicKey: "04eeff"}},
	}
	keysetValue, err := keyset.toCanonicalValue()
	if err != nil {
		t.Fatalf("toCanonicalValue: %v", err)
	}
	keysetDigest, err := jcsSHA256Hex(keysetValue)
	if err != nil {
		t.Fatalf("jcsSHA256Hex(keyset): %v", err)
	}
	workloadID, err := jcsSHA256Hex(keyset.WorkloadIdentity.PublicKey.toCanonicalValue())
	if err != nil {
		t.Fatalf("jcsSHA256Hex(identity): %v", err)
	}
	sigHex := signEndorsement(t, priv, keysetDigest)

	result := verifyKeysetEndorsement(keyset, keysetDigest, workloadID, sigHex, identityKeyHex, "04aabb")
	if result.Err != nil {
		t.Fatalf("verifyKeysetEndorsement: unexpected error: %v", result.Err)
	}
	if !result.EndorsementValid || !result.KeysetDigestMatch || !result.WorkloadIDMatch {
		t.Fatalf("endorsement checks should pass in this scenario: %+v", result)
	}
	if result.SigningKeyInKeyset {
		t.Error("SigningKeyInKeyset = true for a signing key absent from e2ee_public_keys, want false")
	}
}

func TestKeysetContainsE2EEKey(t *testing.T) {
	keyset := &aciWorkloadKeyset{
		E2EEPublicKeys: []aciKey{
			{KeyID: "e2ee-v1", Algo: "secp256k1-aes-256-gcm", PublicKey: "04eeff"},
			{KeyID: "bad-hex", Algo: "secp256k1-aes-256-gcm", PublicKey: "not-hex"},
		},
	}
	tests := []struct {
		name       string
		signingKey string
		want       bool
	}{
		{"member", "04eeff", true},
		{"member uppercase hex", "04EEFF", true},
		{"not a member", "04aabb", false},
		{"empty signing key", "", false},
		{"undecodable signing key", "zz", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keysetContainsE2EEKey(keyset, tt.signingKey); got != tt.want {
				t.Errorf("keysetContainsE2EEKey(%q) = %v, want %v", tt.signingKey, got, tt.want)
			}
		})
	}
}

// TestVerifyACIKeyset_HappyPath exercises the same scenario through the
// public VerifyACIKeyset entry point (RawAttestation → ACIKeysetResult), as
// used by the proxy/verify orchestration.
func TestVerifyACIKeyset_HappyPath(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	identityKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())

	const signingKeyHex = "04eeff"
	keyset := &aciWorkloadKeyset{
		WorkloadIdentity: aciWorkloadIdentity{
			PublicKey: aciPublicKey{Algo: "ecdsa-secp256k1", PublicKey: identityKeyHex},
		},
		KeysetEpoch:        aciKeysetEpoch{Version: 1, NotAfter: json.Number("100")},
		ReceiptSigningKeys: []aciKey{},
		E2EEPublicKeys:     []aciKey{{KeyID: "e2ee-v1", Algo: "secp256k1-aes-256-gcm", PublicKey: signingKeyHex}},
		TLSPublicKeys:      []aciTLSBinding{},
	}
	keysetValue, err := keyset.toCanonicalValue()
	if err != nil {
		t.Fatalf("toCanonicalValue: %v", err)
	}
	keysetDigest, err := jcsSHA256Hex(keysetValue)
	if err != nil {
		t.Fatalf("jcsSHA256Hex(keyset): %v", err)
	}
	workloadID, err := jcsSHA256Hex(keyset.WorkloadIdentity.PublicKey.toCanonicalValue())
	if err != nil {
		t.Fatalf("jcsSHA256Hex(identity): %v", err)
	}
	sigHex := signEndorsement(t, priv, keysetDigest)

	raw := &attestation.RawAttestation{
		BackendFormat:           attestation.FormatACI1,
		SigningKey:              signingKeyHex,
		ACIWorkloadKeyset:       keyset,
		ACIWorkloadKeysetDigest: keysetDigest,
		ACIWorkloadID:           workloadID,
		ACIKeysetEndorsementSig: sigHex,
		ACIIdentityKeyHex:       identityKeyHex,
	}

	result := VerifyACIKeyset(raw)
	if result == nil {
		t.Fatal("VerifyACIKeyset returned nil for ACI/1 attestation")
	}
	if result.Err != nil {
		t.Fatalf("keyset endorsement error: %v", result.Err)
	}
	if !result.EndorsementValid || !result.KeysetDigestMatch || !result.WorkloadIDMatch || !result.SigningKeyInKeyset {
		t.Errorf("expected all checks to pass: %+v", result)
	}
}

func TestVerifyACIKeyset_NonACI(t *testing.T) {
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatDstack}
	result := VerifyACIKeyset(raw)
	if result != nil {
		t.Error("expected nil for non-ACI/1 format")
	}
}

func TestVerifyACIKeyset_NilKeyset(t *testing.T) {
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1}
	result := VerifyACIKeyset(raw)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Err == nil {
		t.Error("expected error for nil keyset")
	}
}

func TestVerifyKeysetEndorsement_ErrorPaths(t *testing.T) {
	ks := &aciWorkloadKeyset{
		WorkloadIdentity: aciWorkloadIdentity{
			PublicKey: aciPublicKey{Algo: "ecdsa-secp256k1", PublicKey: "deadbeef"},
		},
		KeysetEpoch: aciKeysetEpoch{Version: 1, NotAfter: json.Number("100")},
	}

	t.Run("empty signature", func(t *testing.T) {
		result := verifyKeysetEndorsement(ks, "x", "x", "", "aabb", "04eeff")
		if result.Err == nil {
			t.Error("expected error for empty signature")
		}
	})

	t.Run("empty identity key", func(t *testing.T) {
		result := verifyKeysetEndorsement(ks, "x", "x", "aabb", "", "04eeff")
		if result.Err == nil {
			t.Error("expected error for empty identity key")
		}
	})

	t.Run("invalid signature hex", func(t *testing.T) {
		result := verifyKeysetEndorsement(ks, "x", "x", "not-hex", "aabb", "04eeff")
		if result.Err == nil {
			t.Error("expected error for invalid signature hex")
		}
	})

	t.Run("wrong signature length", func(t *testing.T) {
		result := verifyKeysetEndorsement(ks, "x", "x", "aabb", "aabb", "04eeff")
		if result.Err == nil {
			t.Error("expected error for wrong signature length")
		}
	})
}
