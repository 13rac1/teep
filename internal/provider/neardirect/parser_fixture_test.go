package neardirect_test

import (
	"encoding/json"
	"github.com/13rac1/teep/internal/jsonstrict"
	"maps"
	"strings"
	"testing"
)

func directTestResponse(t *testing.T, model string, changes map[string]any) string {
	t.Helper()
	report := map[string]any{
		"model_name": model, "intel_quote": "dGVzdHF1b3Rl", "nvidia_payload": "payload",
		"signing_algo": "ed25519", "signing_public_key": strings.Repeat("bb", 32),
		"signing_address": strings.Repeat("bb", 32), "tls_cert_fingerprint": strings.Repeat("ab", 32),
		"request_nonce": "abcd", "event_log": []any{},
		"info": map[string]any{"app_name": "app", "compose_hash": "ab", "os_image_hash": "ab", "device_id": "ab", "tcb_info": map[string]any{"app_compose": "services: {}"}},
	}
	maps.Copy(report, changes)
	envelope := make(map[string]any, len(report)+1)
	maps.Copy(envelope, report)
	envelope["all_attestations"] = []any{report}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func directFixture(t *testing.T) map[string]any {
	t.Helper()
	var wrapper struct {
		Value map[string]any `json:"value"`
	}
	if _, _, err := jsonstrict.Unmarshal([]byte(`{"value":`+directTestResponse(t, "model", nil)+`}`), &wrapper); err != nil {
		t.Fatal(err)
	}
	return wrapper.Value
}

func encodeDirectFixture(t *testing.T, body map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
