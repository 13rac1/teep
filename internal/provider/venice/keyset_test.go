package venice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
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

func TestNotAfterCanonical(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    uint64
		wantErr bool
	}{
		{"timestamp", "1790265204", 1790265204, false},
		{"uint64 max", "18446744073709551615", 18446744073709551615, false},
		{"float64-rounded uint64 max", "18446744073709552000", 18446744073709551615, false},
		// Any string that rounds to float64(2^64) recovers u64::MAX; the
		// keyset digest cross-check decides whether that was correct.
		{"rounds to uint64 max", "18446744073709552001", 18446744073709551615, false},
		{"out of range", "28446744073709552000", 0, true},
		{"not a number", "not-a-number", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := notAfterCanonical(tc.in)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWorkloadKeyset_ToCanonicalValue(t *testing.T) {
	ks := &aciWorkloadKeyset{
		Subject:            nil,
		NotAfter:           json.Number("18446744073709551615"),
		ReceiptSigningKeys: []aciKey{},
		E2EEPublicKeys:     []aciKey{},
		TLSPublicKeys:      []aciTLSBinding{},
	}

	cv, err := ks.toCanonicalValue()
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonicalize(cv)
	if err != nil {
		t.Fatal(err)
	}

	// Canonical key ordering:
	//   e2ee_public_keys < not_after < receipt_signing_keys < subject < tls_public_keys
	want := `{"e2ee_public_keys":[],"not_after":18446744073709551615,"receipt_signing_keys":[],"subject":null,"tls_public_keys":[]}`
	if string(got) != want {
		t.Errorf("canonical keyset:\n  got:  %s\n  want: %s", got, want)
	}

	d, err := jcsSHA256Hex(cv)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(want))
	expected := "sha256:" + hex.EncodeToString(h[:])
	if d != expected {
		t.Errorf("keyset digest: got %s, want %s", d, expected)
	}
}

// ---------------------------------------------------------------------------
// verifyKeyset / VerifyACIKeyset tests
// ---------------------------------------------------------------------------

// signRecoverable signs keccak256(message) with priv and returns the
// 65-byte r||s||v signature hex that the custody chain carries.
func signRecoverable(t *testing.T, priv *secp256k1.PrivateKey, message []byte) string {
	t.Helper()
	h := sha3.NewLegacyKeccak256()
	h.Write(message)
	// ecdsa.SignCompact returns the recovery byte first; the ACI chain
	// carries it last.
	sig := ecdsa.SignCompact(priv, h.Sum(nil), true)
	return hex.EncodeToString(append(sig[1:], sig[0]))
}

// custodyChain builds a valid two-signature dstack-KMS custody chain for
// e2eeKey: the app key signs the purpose message, the root signs
// "dstack-kms-issued:" || appID || compressed app key. Returns the chain
// and the compressed root hex for the allowlist.
func custodyChain(t *testing.T, root, app *secp256k1.PrivateKey, e2eeKey *secp256k1.PublicKey, appID []byte) (chain []string, rootHex string) {
	t.Helper()
	kmsPubCompressed := hex.EncodeToString(e2eeKey.SerializeCompressed())
	purposeSig := signRecoverable(t, app, []byte(e2eeCustodyPurpose+":"+kmsPubCompressed))
	rootMsg := append([]byte("dstack-kms-issued:"), appID...)
	rootMsg = append(rootMsg, app.PubKey().SerializeCompressed()...)
	rootSig := signRecoverable(t, root, rootMsg)
	return []string{purposeSig, rootSig}, hex.EncodeToString(root.PubKey().SerializeCompressed())
}

// aciTestFixture bundles a self-consistent keyset + custody chain built by
// keysetFixture.
type aciTestFixture struct {
	keyset     *aciWorkloadKeyset
	custody    *aciKeyCustody
	digest     string
	signingKey string
	appID      []byte
	appIDHex   string
	rootHex    string
}

// fixtureNow is a fixed verification time before the fixtures' not_after, so
// the expiry check passes deterministically.
var fixtureNow = time.Unix(1_700_000_000, 0)

// run verifies the fixture with its own root and app-id allowlists.
func (fx *aciTestFixture) run() *attestation.ACIKeysetResult {
	return verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, fx.appID,
		fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
}

// keysetFixture builds a self-consistent keyset + custody + digest around a
// freshly generated E2EE key, signed by fresh app and root keys.
func keysetFixture(t *testing.T) aciTestFixture {
	t.Helper()
	rootPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	appPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	e2eePriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signingKeyHex := hex.EncodeToString(e2eePriv.PubKey().SerializeUncompressed())
	appID := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44}

	keyset := &aciWorkloadKeyset{
		NotAfter:           json.Number("1790265204"),
		ReceiptSigningKeys: []aciKey{},
		E2EEPublicKeys:     []aciKey{{KeyID: "dstack-kms-e2ee-v1", Algo: "secp256k1-aes-256-gcm-hkdf-sha256", PublicKey: signingKeyHex}},
		TLSPublicKeys:      []aciTLSBinding{{Domain: "test.example.com", SPKISHA256: "aabbccdd"}},
	}
	cv, err := keyset.toCanonicalValue()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := jcsSHA256Hex(cv)
	if err != nil {
		t.Fatal(err)
	}

	chain, root := custodyChain(t, rootPriv, appPriv, e2eePriv.PubKey(), appID)
	custody := &aciKeyCustody{
		Provider: "dstack-kms",
		Keys: []aciCustodyKey{{
			Role:           "e2ee-secp256k1",
			Path:           "aci/e2ee/v1",
			Purpose:        e2eeCustodyPurpose,
			Algo:           "secp256k1-aes-256-gcm-hkdf-sha256",
			PublicKey:      signingKeyHex,
			KMSPublicKey:   hex.EncodeToString(e2eePriv.PubKey().SerializeCompressed()),
			SignatureChain: chain,
		}},
	}
	return aciTestFixture{keyset: keyset, custody: custody, digest: digest,
		signingKey: signingKeyHex, appID: appID, appIDHex: hex.EncodeToString(appID), rootHex: root}
}

func TestVerifyKeyset_HappyPath(t *testing.T) {
	fx := keysetFixture(t)
	result := fx.run()
	if result.Err != nil {
		t.Fatalf("verifyKeyset: unexpected error: %v (detail: %s)", result.Err, result.Detail)
	}
	if !result.KeysetDigestMatch || !result.SigningKeyInKeyset || !result.CustodyChainValid ||
		!result.GatewayIdentityValid || !result.KeysetNotExpired {
		t.Errorf("expected all checks to pass: %+v", result)
	}
}

func TestVerifyKeyset_Failures(t *testing.T) {
	t.Run("digest mismatch", func(t *testing.T) {
		fx := keysetFixture(t)
		result := verifyKeyset(fx.keyset, fx.custody, "sha256:0000", fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.KeysetDigestMatch {
			t.Error("KeysetDigestMatch = true for a wrong declared digest")
		}
	})

	t.Run("signing key not in keyset", func(t *testing.T) {
		fx := keysetFixture(t)
		fx.keyset.E2EEPublicKeys = []aciKey{{KeyID: "other", Algo: "x", PublicKey: "04aabb"}}
		cv, err := fx.keyset.toCanonicalValue()
		if err != nil {
			t.Fatal(err)
		}
		digest, err := jcsSHA256Hex(cv)
		if err != nil {
			t.Fatal(err)
		}
		result := verifyKeyset(fx.keyset, fx.custody, digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.SigningKeyInKeyset {
			t.Error("SigningKeyInKeyset = true for a signing key absent from e2ee_public_keys")
		}
	})

	t.Run("root not accepted", func(t *testing.T) {
		fx := keysetFixture(t)
		result := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, fx.appID, fixtureNow, []string{"03" + strings.Repeat("00", 32)}, []string{fx.appIDHex})
		if result.CustodyChainValid {
			t.Error("CustodyChainValid = true for a root outside the allowlist")
		}
	})

	t.Run("wrong app id", func(t *testing.T) {
		fx := keysetFixture(t)
		wrong := []byte("wrong-app-id-bytes--")
		result := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, wrong, fixtureNow, []string{fx.rootHex}, []string{hex.EncodeToString(wrong)})
		if result.CustodyChainValid {
			t.Error("CustodyChainValid = true when the quote-bound app id differs from the endorsed one")
		}
	})

	t.Run("missing app id", func(t *testing.T) {
		fx := keysetFixture(t)
		result := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, nil, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.CustodyChainValid {
			t.Error("CustodyChainValid = true with no app-id event")
		}
	})

	t.Run("app id not accepted", func(t *testing.T) {
		fx := keysetFixture(t)
		result := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, nil)
		if result.CustodyChainValid {
			t.Error("CustodyChainValid = true for an app id outside the accepted list — any KMS tenant would be accepted")
		}
	})

	t.Run("subject names a different app", func(t *testing.T) {
		fx := keysetFixture(t)
		other := "app-id:0xdeadbeef"
		fx.keyset.Subject = &other
		cv, err := fx.keyset.toCanonicalValue()
		if err != nil {
			t.Fatal(err)
		}
		digest, err := jcsSHA256Hex(cv)
		if err != nil {
			t.Fatal(err)
		}
		result := verifyKeyset(fx.keyset, fx.custody, digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.GatewayIdentityValid {
			t.Error("GatewayIdentityValid = true when the keyset subject names a different app")
		}
	})

	t.Run("expired keyset", func(t *testing.T) {
		fx := keysetFixture(t)
		fx.keyset.NotAfter = json.Number("1000")
		cv, err := fx.keyset.toCanonicalValue()
		if err != nil {
			t.Fatal(err)
		}
		digest, err := jcsSHA256Hex(cv)
		if err != nil {
			t.Fatal(err)
		}
		result := verifyKeyset(fx.keyset, fx.custody, digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.KeysetNotExpired {
			t.Error("KeysetNotExpired = true for a keyset whose not_after is in the past")
		}
	})

	t.Run("custody key differs from signing key", func(t *testing.T) {
		fx := keysetFixture(t)
		other, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		fx.custody.Keys[0].PublicKey = hex.EncodeToString(other.PubKey().SerializeUncompressed())
		result := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.CustodyChainValid {
			t.Error("CustodyChainValid = true when the custody entry describes a different key")
		}
	})

	t.Run("tampered purpose signature", func(t *testing.T) {
		fx := keysetFixture(t)
		sig, err := hex.DecodeString(fx.custody.Keys[0].SignatureChain[0])
		if err != nil {
			t.Fatal(err)
		}
		sig[10] ^= 0xff
		fx.custody.Keys[0].SignatureChain[0] = hex.EncodeToString(sig)
		result := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.CustodyChainValid {
			t.Error("CustodyChainValid = true for a tampered purpose signature")
		}
	})

	t.Run("wrong custody provider", func(t *testing.T) {
		fx := keysetFixture(t)
		fx.custody.Provider = "other-kms"
		result := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.CustodyChainValid {
			t.Error("CustodyChainValid = true for an unsupported custody provider")
		}
	})

	t.Run("no e2ee custody entry", func(t *testing.T) {
		fx := keysetFixture(t)
		fx.custody.Keys[0].Purpose = "aci.receipt.v1"
		result := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
		if result.CustodyChainValid {
			t.Error("CustodyChainValid = true with no entry for the e2ee purpose")
		}
	})
}

func TestVerifyACIKeyset_NonACI(t *testing.T) {
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatDstack}
	if result := VerifyACIKeyset(raw, fixtureNow); result != nil {
		t.Error("expected nil for non-ACI/1 format")
	}
}

func TestVerifyACIKeyset_MissingStructs(t *testing.T) {
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1}
	result := VerifyACIKeyset(raw, fixtureNow)
	if result == nil || result.Err == nil {
		t.Fatalf("expected an error result for a missing keyset, got %+v", result)
	}
}

func TestVerifyACIKeyset_HappyPath(t *testing.T) {
	fx := keysetFixture(t)
	raw := &attestation.RawAttestation{
		BackendFormat:           attestation.FormatACI1,
		SigningKey:              fx.signingKey,
		ACIWorkloadKeyset:       fx.keyset,
		ACIKeyCustody:           fx.custody,
		ACIWorkloadKeysetDigest: fx.digest,
		GatewayEventLog: []attestation.EventLogEntry{
			{IMR: 3, Event: "app-id", EventPayload: hex.EncodeToString(fx.appID)},
		},
	}

	// The default allowlist does not contain the test root, so the custody
	// chain must be rejected...
	result := VerifyACIKeyset(raw, fixtureNow)
	if result == nil || result.Err != nil {
		t.Fatalf("VerifyACIKeyset: %+v", result)
	}
	if result.CustodyChainValid {
		t.Error("CustodyChainValid = true for a root outside the default allowlist")
	}
	if !result.KeysetDigestMatch || !result.SigningKeyInKeyset {
		t.Errorf("digest/membership should pass: %+v", result)
	}

	// ...and the full chain must verify against the matching allowlist.
	direct := verifyKeyset(fx.keyset, fx.custody, fx.digest, fx.signingKey, fx.appID, fixtureNow, []string{fx.rootHex}, []string{fx.appIDHex})
	if !direct.CustodyChainValid {
		t.Errorf("CustodyChainValid = false with the correct root allowed: %s", direct.Detail)
	}
}

// TestVerifyACIKeyset_LiveSample replays the workload keyset, custody chain,
// and app id captured from a live Venice ACI/1 attestation (2026-08-25,
// model e2ee-glm-5-2-p) through the full verification, pinning the digest
// scheme, the custody chain construction, and the default KMS root
// allowlist against real provider data.
func TestVerifyACIKeyset_LiveSample(t *testing.T) {
	data, err := os.ReadFile("testdata/aci_keyset_live.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		WorkloadKeysetDigest string            `json:"workload_keyset_digest"`
		SigningPublicKey     string            `json:"signing_public_key"`
		AppID                string            `json:"app_id"`
		WorkloadKeyset       aciWorkloadKeyset `json:"workload_keyset"`
		KeyCustody           aciKeyCustody     `json:"key_custody"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&fx); err != nil {
		t.Fatal(err)
	}
	appID, err := hex.DecodeString(fx.AppID)
	if err != nil {
		t.Fatal(err)
	}

	result := verifyKeyset(&fx.WorkloadKeyset, &fx.KeyCustody, fx.WorkloadKeysetDigest,
		fx.SigningPublicKey, appID, fixtureNow, defaultACIKMSRootAllow, defaultACIGatewayAppIDAllow)
	if result.Err != nil {
		t.Fatalf("verifyKeyset(live sample): %v", result.Err)
	}
	if !result.KeysetDigestMatch || !result.SigningKeyInKeyset || !result.CustodyChainValid ||
		!result.GatewayIdentityValid || !result.KeysetNotExpired {
		t.Errorf("live sample must verify fully: %s", result.Detail)
	}
}

func TestAppIDFromEventLog(t *testing.T) {
	runtime := func(event, payload string) attestation.EventLogEntry {
		return attestation.EventLogEntry{IMR: 3, EventType: attestation.DstackRuntimeEventType, Event: event, EventPayload: payload}
	}
	t.Run("single runtime app-id", func(t *testing.T) {
		got, err := appIDFromEventLog([]attestation.EventLogEntry{runtime("app-id", "1122")})
		if err != nil || hex.EncodeToString(got) != "1122" {
			t.Errorf("got %x err %v, want 1122", got, err)
		}
	})
	t.Run("wrong event type is ignored", func(t *testing.T) {
		// An "app-id" event of a non-runtime type carries an unchecked digest.
		got, err := appIDFromEventLog([]attestation.EventLogEntry{
			{IMR: 3, EventType: 0x1, Event: "app-id", EventPayload: "dead"},
		})
		if err != nil || got != nil {
			t.Errorf("got %x err %v, want nil (non-runtime app-id ignored)", got, err)
		}
	})
	t.Run("duplicate is rejected", func(t *testing.T) {
		_, err := appIDFromEventLog([]attestation.EventLogEntry{
			runtime("app-id", "1122"), runtime("app-id", "3344"),
		})
		if err == nil {
			t.Error("expected an error for duplicate app-id events")
		}
	})
	t.Run("absent returns nil", func(t *testing.T) {
		got, err := appIDFromEventLog([]attestation.EventLogEntry{runtime("system-ready", "")})
		if err != nil || got != nil {
			t.Errorf("got %x err %v, want nil,nil", got, err)
		}
	})
}
