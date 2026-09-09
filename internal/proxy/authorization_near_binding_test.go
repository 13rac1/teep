package proxy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestAuthorizationNearModelKeyBinding(t *testing.T) {
	original := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	substitute := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	fingerprint := make([]byte, 32)
	nonce := attestation.NewNonce()
	hash := sha256.Sum256(append(original, fingerprint...))
	var reportData [64]byte
	copy(reportData[:32], hash[:])
	copy(reportData[32:], nonce[:])
	for _, name := range []string{"neardirect", "nearcloud"} {
		t.Run(name, func(t *testing.T) {
			raw := &attestation.RawAttestation{SigningAlgo: "ed25519", SigningAddress: hex.EncodeToString(original), SigningKey: hex.EncodeToString(substitute), TLSFingerprint: hex.EncodeToString(fingerprint)}
			_, bindingErr := (neardirect.ReportDataVerifier{}).VerifyReportData(reportData, raw, nonce)
			if bindingErr == nil {
				t.Fatal("substituted model key passed binding")
			}
			route, err := provider.NewResolvedRoute("https://model.near.ai", "")
			if err != nil {
				t.Fatal(err)
			}
			key, err := route.AuthorizationKey(name, "model")
			if err != nil {
				t.Fatal(err)
			}
			// The unit policy allows the failed factor. E2EE admission still
			// requires successful binding of the key it will retain.
			report := &attestation.VerificationReport{Provider: name, Model: "model", TLSAuthority: route.Authority(), TLSKeyFP: strings.Repeat("ab", 32), Factors: []attestation.FactorResult{{Name: "tee_reportdata_binding", Status: attestation.Fail, Detail: bindingErr.Error(), Enforced: false}}}
			for _, force := range []bool{false, true} {
				value, err := newAuthorization(key, report, raw.SigningKey, true, force)
				if err == nil || value != nil {
					t.Fatal("E2EE admitted an unauthenticated model key")
				}
			}
			if name == "neardirect" {
				if _, err := newAuthorization(key, report, raw.SigningKey, false, false); err != nil {
					t.Fatalf("TLS-only factor allowance changed: %v", err)
				}
			}
		})
	}
}
