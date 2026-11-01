package chutes_test

import (
	"context"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/chutes/chutestest"
)

// The GPU evidence of every direct Chutes capture answers
// SHA256(client_nonce_hex + e2e_pubkey) and verifies against it; the client
// nonce itself is not the SPDM requester nonce.
func TestGPURequesterNonce(t *testing.T) {
	for _, c := range chutestest.Captures(t, "../../integration/testdata") {
		t.Run(c.Name, func(t *testing.T) {
			requester, err := chutes.GPURequesterNonce(c.Nonce, c.Raw.SigningKey)
			if err != nil {
				t.Fatal(err)
			}
			derived := attestation.VerifyNVIDIAGPUDirect(context.Background(), c.Raw.GPUEvidence, c.Nonce, requester)
			if derived.SignatureErr != nil {
				t.Errorf("derived requester nonce: SignatureErr = %v, want nil", derived.SignatureErr)
			}
			if got, want := derived.Nonce, c.Nonce.Hex(); got != want {
				t.Errorf("reported nonce = %s, want %s", got, want)
			}
			plain := attestation.VerifyNVIDIAGPUDirect(context.Background(), c.Raw.GPUEvidence, c.Nonce, c.Nonce)
			if plain.SignatureErr == nil {
				t.Error("GPU evidence verified against the client nonce itself")
			}
		})
	}
}

// The chutes format that a gateway relays carries the gateway's own nonce,
// and its GPU evidence answers that nonce, not the client's: with the client
// nonce the evidence fails. Phala Cloud capture of 2026-06-10.
func TestGPURequesterNonceGatewayChutesFormat(t *testing.T) {
	dir := "../../integration/testdata/phalacloud_phala_deepseek-v3.2_20260610_014917"
	manifest, entries, err := capture.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	clientNonce, err := attestation.ParseNonce(manifest.NonceHex)
	if err != nil {
		t.Fatal(err)
	}
	var report []byte
	for _, e := range entries {
		if strings.Contains(e.URL, "/v1/attestation/report") {
			report = e.Body
		}
	}
	if report == nil {
		t.Fatal("no attestation report in the capture")
	}
	raw, err := provider.ParseChutesFormat(context.Background(), report, "phalacloud")
	if err != nil {
		t.Fatal(err)
	}
	if raw.Nonce == clientNonce.Hex() {
		t.Fatal("the capture echoes the client nonce; the test needs the server nonce")
	}
	requester, err := chutes.GPURequesterNonce(clientNonce, raw.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	if r := attestation.VerifyNVIDIAGPUDirect(context.Background(), raw.GPUEvidence, clientNonce, requester); r.SignatureErr == nil {
		t.Error("GPU evidence of the server nonce verified against the client nonce")
	}
}

func TestGPURequesterNonceRefusesEmptyKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"empty key", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := chutes.GPURequesterNonce(attestation.NewNonce(), tc.key); err == nil {
				t.Error("GPURequesterNonce: err = nil, want an error")
			}
		})
	}
}
