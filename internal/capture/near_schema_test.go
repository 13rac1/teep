package capture

import (
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict"
)

func TestNearCaptureSchema(t *testing.T) {
	for _, body := range []string{
		`{"near_config":{"origin":"https://api.near.ai"}}`,
		`{"near_config":{"origin":"https://api.near.ai","e2ee":null}}`,
		`{"near_config":{"origin":"https://api.near.ai","e2ee":false,"E2EE":true}}`,
		`{"near_config":{"origin":"https://api.near.ai","e2ee":false,"e2ee":true}}`,
		`{"near_route":{"mode":"static","authority":"example.com","index":null}}`,
		`{"near_route":{"mode":"static","authority":"example.com","index":0}}`,
		`{"near_route":{"mode":"explicit","authority":"model-i0.completions.near.ai","canonical":"model.completions.near.ai"}}`,
		`{"near_route":{"mode":"discovered","authority":"model-i0.completions.near.ai","canonical":"model.completions.near.ai","index":1e0}}`,
	} {
		var manifest Manifest
		if _, _, err := jsonstrict.Unmarshal([]byte(body), &manifest); err == nil {
			t.Fatal("accepted invalid NEAR capture schema")
		}
	}
	for _, body := range []string{
		`{"near_config":{"origin":"https://api.near.ai","e2ee":false}}`,
		`{"near_route":{"mode":"static","authority":"example.com"}}`,
		`{"near_route":{"mode":"explicit","authority":"model-i0.completions.near.ai","canonical":"model.completions.near.ai","index":0}}`,
		`{"near_route":{"mode":"explicit","authority":"model-i18446744073709551615.completions.near.ai","canonical":"model.completions.near.ai","index":18446744073709551615}}`,
	} {
		var manifest Manifest
		if _, _, err := jsonstrict.Unmarshal([]byte(body), &manifest); err != nil {
			t.Fatal(err)
		}
	}
}
