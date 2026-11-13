package chutes_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict/aliastest"
	"github.com/13rac1/teep/internal/provider/chutes"
)

// Chutes evidence with a member that differs from a defined one only in
// letter case is refused (the CaseFoldError of github.com/13rac1/jsonstrict).
func TestParseAttestationResponseRefusesFoldedAlias(t *testing.T) {
	dir := "../../integration/testdata/current/chutes_chutes/responses/"
	instances := aliastest.Read(t, dir+"0001_api.chutes.ai_e2e_instances_e51e818e-fa63-570d-9f68-49d7d1b4d12f.body")
	evidence := aliastest.Read(t, dir+"0002_api.chutes.ai_chutes_e51e818e-fa63-570d-9f68-49d7d1b4d12f_evidence.body")
	_, err := chutes.ParseAttestationResponse(context.Background(), instances, aliastest.Append(t, evidence, "Failed_Instance_IDs", `[]`), attestation.NewNonce())
	aliastest.Refused(t, err)
}
