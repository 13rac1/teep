package tinfoil

import (
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict/aliastest"
)

// A Tinfoil v3 document with a member that differs from a defined one only
// in letter case is refused (the CaseFoldError of github.com/13rac1/jsonstrict).
func TestParseV3DocumentRefusesFoldedAlias(t *testing.T) {
	body := aliastest.Read(t, "../../integration/testdata/current/tinfoil_v3_cloud_tinfoil/responses/0001_inference.tinfoil.sh_.well-known_tinfoil-attestation.body")
	_, err := parseV3Document(aliastest.Append(t, body, "Format", `"x"`))
	aliastest.Refused(t, err)
}
