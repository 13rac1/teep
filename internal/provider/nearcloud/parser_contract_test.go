package nearcloud_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider/nearcloud"
)

func encodeCloudFixture(t *testing.T, body map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestCloudEnvelopeRepresentations(t *testing.T) {
	for _, field := range []string{"model_name", "intel_quote", "nvidia_payload", "signing_public_key", "signing_address", "signing_algo", "tls_cert_fingerprint", "request_nonce", "event_log", "info", "all_attestations"} {
		for _, value := range []any{nil, "", []any{}} {
			t.Run(field, func(t *testing.T) {
				body := cloudFixture(t)
				body[field] = value
				if _, _, err := nearcloud.ParseGatewayResponse(t.Context(), encodeCloudFixture(t, body), "m"); err == nil {
					t.Fatal("accepted mixed envelope")
				}
			})
		}
	}
	for _, value := range []any{nil, []any{}, []any{nil}, []any{map[string]any{"model_name": "m"}}} {
		t.Run("invalid_models", func(t *testing.T) {
			body := cloudFixture(t)
			body["model_attestations"] = value
			if _, _, err := nearcloud.ParseGatewayResponse(t.Context(), encodeCloudFixture(t, body), "m"); err == nil {
				t.Fatal("accepted malformed model array")
			}
		})
	}
}

func TestCloudValidatesEveryModel(t *testing.T) {
	for _, mode := range []string{"different_model", "duplicate_model", "malformed_unselected"} {
		t.Run(mode, func(t *testing.T) {
			body := cloudFixture(t)
			other := cloudFixture(t)["model_attestations"].([]any)[0].(map[string]any)
			if mode != "duplicate_model" {
				other["model_name"] = "other"
			}
			if mode == "malformed_unselected" {
				other["info"] = nil
			}
			body["model_attestations"] = append(body["model_attestations"].([]any), other)
			_, raw, err := nearcloud.ParseGatewayResponse(t.Context(), encodeCloudFixture(t, body), "m")
			if mode == "different_model" {
				if err != nil || raw.Model != "m" {
					t.Fatalf("selection: %v", err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid alternative")
			}
		})
	}
}

func TestCloudNestedStructures(t *testing.T) {
	for _, location := range []string{"info", "tcb_info", "event_log"} {
		for _, defect := range []string{"missing", "null", "duplicate", "escaped_duplicate"} {
			t.Run(location+"/"+defect, func(t *testing.T) {
				body := cloudFixture(t)
				gateway := body["gateway_attestation"].(map[string]any)
				target := gateway
				if location == "tcb_info" {
					target = gateway["info"].(map[string]any)
				}
				switch defect {
				case "missing":
					delete(target, location)
				case "null":
					target[location] = nil
				default:
					name := "app_compose"
					if location == "info" {
						name = "app_name"
					}
					second := name
					if defect == "escaped_duplicate" {
						second = `\u0061` + name[1:]
					}
					encoded := `{"` + name + `":"a","` + second + `":"b"}`
					if location == "event_log" {
						second = "imr"
						if defect == "escaped_duplicate" {
							second = `\u0069mr`
						}
						encoded = `[{"imr":0,"` + second + `":1}]`
					}
					if location == "info" {
						target[location] = json.RawMessage(encoded)
					} else {
						target[location] = encoded
					}
				}
				if _, _, err := nearcloud.ParseGatewayResponse(t.Context(), encodeCloudFixture(t, body), "m"); err == nil {
					t.Fatal("accepted invalid nested gateway evidence")
				}
			})
		}
	}
}

func TestCloudUnknownNestedFields(t *testing.T) {
	body := cloudFixture(t)
	gateway := body["gateway_attestation"].(map[string]any)
	info := gateway["info"].(map[string]any)
	info["extra"] = true
	info["tcb_info"] = `{"app_compose":"test-compose","extra":true}`
	gateway["event_log"] = `[{"imr":0,"digest":"ab","event_type":1,"event":"","event_payload":"","extra":true}]`
	_, raw, err := nearcloud.ParseGatewayResponse(t.Context(), encodeCloudFixture(t, body), "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.UnknownFields) != 3 {
		t.Fatalf("unknown fields: %v", raw.UnknownFields)
	}
	for _, field := range raw.UnknownFields {
		if !strings.HasPrefix(field, "nearcloud.gateway_attestation.") {
			t.Fatalf("missing field path: %s", field)
		}
	}
}
