package neardirect

import (
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict/aliastest"
)

// An endpoint list whose entry has a member that differs from a defined one
// only in letter case is refused, also through nearparse.Object, which
// removes other unknown members (jsonstrict.UnmarshalObject).
func TestParseEndpointMappingRefusesFoldedAlias(t *testing.T) {
	_, err := parseEndpointMapping([]byte(`{"endpoints":[{"domain":"a.completions.near.ai","models":["m"],"Domain":"b.example.com"}]}`), true)
	aliastest.Refused(t, err)
}
