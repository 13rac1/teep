package nearcloud_test

import (
	"encoding/json"
	"maps"
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict"
)

func cloudFixture(t *testing.T) map[string]any {
	t.Helper()
	var wrapper struct {
		Value map[string]any `json:"value"`
	}
	if _, _, err := jsonstrict.Unmarshal([]byte(`{"value":`+minimalGatewayJSON("m", "abc", "fp")+`}`), &wrapper); err != nil {
		t.Fatal(err)
	}
	return wrapper.Value
}

func cloudTestResponse(t *testing.T, changes map[string]any) []byte {
	t.Helper()
	body := cloudFixture(t)
	gateway := body["gateway_attestation"].(map[string]any)
	maps.Copy(gateway, changes)
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func cloudModelsResponse(t *testing.T, models json.RawMessage) []byte {
	t.Helper()
	body := cloudFixture(t)
	body["model_attestations"] = models
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
