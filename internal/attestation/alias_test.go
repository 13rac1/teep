package attestation

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/jsonstrict/aliastest"
)

// An NVIDIA EAT payload and Proof of Cloud claims with a member that
// differs from a defined one only in letter case are refused
// (the CaseFoldError of github.com/13rac1/jsonstrict). The alias follows the defined member.
func TestLegacyParsersRefuseFoldedAliases(t *testing.T) {
	nonce := NewNonce()
	eat := `{"arch":"HOPPER","nonce":"` + nonce.Hex() + `","evidence_list":[],"Arch":"BLACKWELL"}`
	result := verifyNVIDIAEAT(context.Background(), eat, nonce)
	aliastest.Refused(t, result.SignatureErr)

	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"machine_id":"a","quote_hash":"b","Machine_ID":"c"}`))
	_, err := verifyPoCJWTClaimsAt(context.Background(), "e30."+claims+".sig", "00", "a", time.Now())
	aliastest.Refused(t, err)
}
