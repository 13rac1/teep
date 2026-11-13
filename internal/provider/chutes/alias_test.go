package chutes_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict/aliastest"
	"github.com/13rac1/teep/internal/provider/chutes"
)

// Chutes evidence with a member that differs from a defined one only in
// letter case is refused (the CaseFoldError of github.com/13rac1/jsonstrict).
func TestParseAttestationResponseRefusesFoldedAlias(t *testing.T) {
	dir := "../../integration/testdata/current/chutes_chutes/responses/"
	instances := aliastest.Read(t, onlyFile(t, dir+"*_api.chutes.ai_e2e_instances_*.body"))
	evidence := aliastest.Read(t, onlyFile(t, dir+"*_api.chutes.ai_chutes_*_evidence.body"))
	_, err := chutes.ParseAttestationResponse(context.Background(), instances, aliastest.Append(t, evidence, "Failed_Instance_IDs", `[]`), attestation.NewNonce())
	aliastest.Refused(t, err)
}

// onlyFile returns the one file that pattern matches.
func onlyFile(t *testing.T, pattern string) string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) != 1 {
		t.Fatalf("%s: %d matches, %v", pattern, len(matches), err)
	}
	return matches[0]
}
