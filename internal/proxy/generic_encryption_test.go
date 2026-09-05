package proxy

import (
	"encoding/hex"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/tinfoil"
)

func TestGenericInferenceRejectsEHBP(t *testing.T) {
	key := authorizedTestKey(t)
	prov := &provider.Provider{Name: "tinfoil_v3_direct", E2EE: true, Encryptor: tinfoil.NewE2EE()}
	server := &Server{}
	raw := &attestation.RawAttestation{SigningKey: hex.EncodeToString(key.PublicKey().Bytes())}
	result, err := server.buildUpstreamBody(t.Context(), []byte(`{"model":"model"}`), "model", true, prov, raw, e2ee.EndpointChat)
	if err == nil || result != nil {
		t.Fatal("generic inference accepted encryption that requires authorized inference")
	}
}
