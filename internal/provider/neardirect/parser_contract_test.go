package neardirect_test

import (
	"encoding/json"
	"github.com/13rac1/teep/internal/attestation"
	"strconv"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestDirectEnvelopeRepresentations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"flat_only", func(b map[string]any) { delete(b, "all_attestations") }},
		{"array_only", func(b map[string]any) {
			for k := range b {
				if k != "all_attestations" {
					delete(b, k)
				}
			}
		}},
		{"null_array", func(b map[string]any) { b["all_attestations"] = nil }},
		{"empty_array", func(b map[string]any) { b["all_attestations"] = []any{} }},
		{"null_entry", func(b map[string]any) { b["all_attestations"] = []any{nil} }},
		{"two_entries", func(b map[string]any) { a := b["all_attestations"].([]any); b["all_attestations"] = append(a, a[0]) }},
		{"both_arrays", func(b map[string]any) { b["model_attestations"] = nil }},
		{"gateway_mixture", func(b map[string]any) { b["gateway_attestation"] = nil }},
		{"missing_flat_field", func(b map[string]any) { delete(b, "signing_public_key") }},
		{"null_flat_field", func(b map[string]any) { b["signing_public_key"] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := directFixture(t)
			tc.change(body)
			if raw, err := neardirect.ParseAttestationResponse(t.Context(), encodeDirectFixture(t, body), "model"); err == nil || raw != nil {
				t.Fatal("accepted unsupported representation")
			}
		})
	}
}

func TestDirectRepeatedFieldAgreement(t *testing.T) {
	for _, group := range []string{"model_name", "intel_quote", "nvidia_payload", "signing_algo", "signing_public_key", "signing_address", "tls_cert_fingerprint", "request_nonce", "event_log", "info", "tcb_info"} {
		t.Run(group, func(t *testing.T) {
			body := directFixture(t)
			repeated := body["all_attestations"].([]any)[0].(map[string]any)
			switch group {
			case "event_log":
				repeated[group] = []any{map[string]any{"imr": 0, "event_type": 1, "digest": "abcd", "event": "x", "event_payload": ""}}
			case "info":
				repeated["info"].(map[string]any)["app_name"] = "different"
			case "tcb_info":
				repeated["info"].(map[string]any)["tcb_info"].(map[string]any)["app_compose"] = "different"
			default:
				repeated[group] = "cdef"
			}
			if _, err := neardirect.ParseAttestationResponse(t.Context(), encodeDirectFixture(t, body), "model"); err == nil {
				t.Fatal("accepted disagreement")
			}
		})
	}
}

func TestDirectNestedStructure(t *testing.T) {
	for _, path := range []string{"info", "tcb_info", "event_log"} {
		for _, malformed := range []string{"missing", "null", "duplicate", "escaped_duplicate"} {
			t.Run(path+"/"+malformed, func(t *testing.T) {
				body := directFixture(t)
				repeated := body["all_attestations"].([]any)[0].(map[string]any)
				target := repeated
				if path == "tcb_info" {
					target = repeated["info"].(map[string]any)
				}
				switch malformed {
				case "missing":
					delete(target, path)
				case "null":
					target[path] = nil
				default:
					field := "app_name"
					if path == "tcb_info" {
						field = "app_compose"
					}
					duplicate := field
					if malformed == "escaped_duplicate" {
						duplicate = `\u0061` + field[1:]
					}
					value := `{"` + field + `":"a","` + duplicate + `":"b"}`
					if path == "event_log" {
						value = `[{"imr":0,"imr":1}]`
					}
					if path == "tcb_info" {
						target[path] = value
					} else {
						target[path] = json.RawMessage(value)
					}
				}
				if _, err := neardirect.ParseAttestationResponse(t.Context(), encodeDirectFixture(t, body), "model"); err == nil {
					t.Fatal("accepted malformed nested structure")
				}
			})
		}
	}
}

func TestDirectUnknownFieldsAndEquivalentEncoding(t *testing.T) {
	body := directFixture(t)
	repeated := body["all_attestations"].([]any)[0].(map[string]any)
	repeated["signing_public_key"] = strings.ToUpper(repeated["signing_public_key"].(string))
	info := repeated["info"].(map[string]any)
	info["unverified_addition"] = "ignored"
	info["APP_NAME"] = "must not override app_name"
	info["tcb_info"] = `{"app_compose":"services: {}","extra":true}`
	raw, err := neardirect.ParseAttestationResponse(t.Context(), encodeDirectFixture(t, body), "model")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.UnknownFields) != 3 {
		t.Fatalf("unknown fields: %v", raw.UnknownFields)
	}
	if raw.AppName != "app" || raw.AppCompose != "services: {}" {
		t.Fatal("unknown field changed verification inputs")
	}
	for _, field := range raw.UnknownFields {
		if !strings.HasPrefix(field, "neardirect.all_attestations[0].info.") {
			t.Fatalf("missing field path: %s", field)
		}
	}
}

func TestDirectCompleteInfoAgreement(t *testing.T) {
	for _, location := range []string{"info", "tcb_info"} {
		fields := []string{"app_name", "app_cert", "app_id", "instance_id", "key_provider_info", "mr_aggregated", "vm_config", "compose_hash", "os_image_hash", "device_id"}
		if location == "tcb_info" {
			fields = []string{"app_compose", "compose_hash", "os_image_hash", "device_id", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"}
		}
		for _, field := range fields {
			t.Run(location+"/"+field, func(t *testing.T) {
				body := directFixture(t)
				repeated := body["all_attestations"].([]any)[0].(map[string]any)
				info := repeated["info"].(map[string]any)
				if location == "tcb_info" {
					info = info["tcb_info"].(map[string]any)
				}
				info[field] = "cdef"
				if _, err := neardirect.ParseAttestationResponse(t.Context(), encodeDirectFixture(t, body), "model"); err == nil {
					t.Fatal("supported field was excluded from comparison")
				}
			})
		}
	}
}

func TestDirectOrderedEvents(t *testing.T) {
	first := map[string]any{"imr": 0, "event_type": 1, "digest": "abcd", "event": "first", "event_payload": "ab"}
	second := map[string]any{"imr": 1, "event_type": 2, "digest": "cdef", "event": "second", "event_payload": "cd"}
	for _, nested := range []bool{false, true} {
		t.Run(strconv.FormatBool(nested), func(t *testing.T) {
			body := directFixture(t)
			repeated := body["all_attestations"].([]any)[0].(map[string]any)
			a, b := body, repeated
			if nested {
				a = body["info"].(map[string]any)["tcb_info"].(map[string]any)
				b = repeated["info"].(map[string]any)["tcb_info"].(map[string]any)
			}
			a["event_log"] = []any{first, second}
			b["event_log"] = []any{second, first}
			if _, err := neardirect.ParseAttestationResponse(t.Context(), encodeDirectFixture(t, body), "model"); err == nil {
				t.Fatal("accepted reordered events")
			}
		})
	}
}

func TestDirectSchemaAllowancePreservesDiagnostics(t *testing.T) {
	body := directFixture(t)
	body["info"].(map[string]any)["extra"] = true
	raw, err := neardirect.ParseAttestationResponse(t.Context(), encodeDirectFixture(t, body), "model")
	if err != nil {
		t.Fatal(err)
	}
	report := attestation.BuildReport(&attestation.ReportInput{Provider: "neardirect", Model: "model", Raw: raw, AllowFail: []string{"response_schema"}})
	for _, factor := range report.Factors {
		if factor.Name == "response_schema" {
			if factor.Enforced || factor.Status != attestation.Fail {
				t.Fatalf("schema allowance lost diagnostics: %+v", factor)
			}
			return
		}
	}
	t.Fatal("missing response_schema factor")
}

func TestDirectComposeServicesRejectNullElements(t *testing.T) {
	for _, tc := range []struct {
		name     string
		services any
		valid    bool
	}{
		{"strings", []string{"model", "relay"}, true},
		{"empty", []string{}, true},
		{"null_array", nil, false},
		{"null_element", []any{nil}, false},
		{"mixed_null", []any{"model", nil}, false},
		{"number", []any{1}, false},
		{"object", []any{map[string]any{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := directFixture(t)
			body["compose_manager_attestation"] = map[string]any{
				"actions":      []any{map[string]any{"timestamp": "2026-09-10", "action": "restart", "services": tc.services}},
				"actions_hash": "", "nonce": "", "nonce_source": "", "quote": "", "event_log": "", "report_data": "", "vm_config": "",
			}
			raw, err := neardirect.ParseAttestationResponse(t.Context(), encodeDirectFixture(t, body), "model")
			if (err == nil) != tc.valid {
				t.Fatalf("service array validity: %v", err)
			}
			if !tc.valid && raw != nil {
				t.Fatal("malformed services published evidence")
			}
		})
	}
}
