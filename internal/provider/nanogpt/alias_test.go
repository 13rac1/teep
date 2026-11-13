package nanogpt_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict/aliastest"
	"github.com/13rac1/teep/internal/provider/nanogpt"
)

// A dstack attestation with a member that differs from a defined one only
// in letter case is refused (the CaseFoldError of github.com/13rac1/jsonstrict).
func TestParseAttestationResponseRefusesFoldedAlias(t *testing.T) {
	body := aliastest.Read(t, "../../integration/testdata/venice_e2ee-qwen3-5-122b-a10b_20260610_014707/responses/0001_api.venice.ai_api_v1_tee_attestation.body")
	_, err := nanogpt.ParseAttestationResponse(context.Background(), aliastest.Append(t, body, "All_Attestations", `[]`))
	aliastest.Refused(t, err)
}
