package attestation

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// aciGatewayVariantRaw is an ACI/1 RawAttestation of the gateway variant:
// no echoed nonce or model.
func aciGatewayVariantRaw(t *testing.T) *RawAttestation {
	t.Helper()
	raw := aciGatewayRaw(NewNonce(), validSigningKey(t))
	raw.Nonce = ""
	raw.Model = ""
	raw.GatewayNonceHex = ""
	return raw
}

func buildACIReport(raw *RawAttestation, nonce Nonce, gatewayTDX *TDXVerifyResult, nvidia *NvidiaVerifyResult) *VerificationReport {
	return BuildReport(&ReportInput{
		Provider:              "phalacloud",
		Model:                 "test-model",
		Raw:                   raw,
		Nonce:                 nonce,
		AllowFail:             ACIDefaultAllowFail,
		GatewayTDX:            gatewayTDX,
		GatewayNonceHex:       raw.GatewayNonceHex,
		GatewayNonce:          nonce,
		Nvidia:                nvidia,
		E2EEKeyBoundByGateway: true,
	})
}

// Without an echoed nonce, an ACI/1 report evaluates the client nonce where
// the evidence binds it: the verified gateway REPORTDATA, and the GPU
// evidence when it carries a nonce. The missing echo alone is not a failure.
func TestBuildReport_ACINonceWithoutEcho(t *testing.T) {
	nonce := NewNonce()
	bound := &TDXVerifyResult{TeeTCBSVN: make([]byte, 16), ReportDataBindingDetail: "REPORTDATA binds enclave key and nonce"}
	unbound := &TDXVerifyResult{TeeTCBSVN: make([]byte, 16), ReportDataBindingErr: errors.New("REPORTDATA[32:64] mismatch")}
	other := NewNonce()
	for _, tc := range []struct {
		name       string
		gatewayTDX *TDXVerifyResult
		nvidia     *NvidiaVerifyResult
		status     Status
		detail     string
	}{
		{"REPORTDATA only", bound, nil, Pass, "the gateway quote REPORTDATA binds the client nonce (no GPU evidence nonce)"},
		{"REPORTDATA and GPU evidence", bound, &NvidiaVerifyResult{Nonce: nonce.Hex()}, Pass, "the gateway quote REPORTDATA and the GPU evidence bind the client nonce"},
		{"GPU evidence nonce differs", bound, &NvidiaVerifyResult{Nonce: other.Hex()}, Fail, "is not the client nonce"},
		{"REPORTDATA binding failed", unbound, &NvidiaVerifyResult{Nonce: nonce.Hex()}, Fail, "REPORTDATA binding of the client nonce did not verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := buildACIReport(aciGatewayVariantRaw(t), nonce, tc.gatewayTDX, tc.nvidia)
			for _, name := range []string{FactorNonceMatch, FactorGWNonceMatch} {
				f := findFactor(t, report, name)
				if f.Status != tc.status || !strings.Contains(f.Detail, tc.detail) {
					t.Errorf("%s = %v %q, want %v with %q", name, f.Status, f.Detail, tc.status, tc.detail)
				}
			}
		})
	}
}

// A format other than ACI/1 without an echoed nonce still fails nonce_match.
func TestBuildReport_NonACIMissingNonceFails(t *testing.T) {
	nonce := NewNonce()
	report := BuildReport(&ReportInput{
		Provider: "venice", Model: "m", Nonce: nonce, AllowFail: DefaultAllowFail,
		Raw: &RawAttestation{BackendFormat: FormatDstack, Model: "m"},
	})
	if f := findFactor(t, report, FactorNonceMatch); f.Status != Fail || !strings.Contains(f.Detail, "nonce field absent") {
		t.Fatalf("nonce_match = %v %q, want Fail for a dstack response without a nonce", f.Status, f.Detail)
	}
}

// aci_backend_named states whether the attestation names a backend for the
// requested model, and is allowed to fail by default for ACI/1.
func TestBuildReport_ACIBackendNamed(t *testing.T) {
	nonce := NewNonce()
	bound := &TDXVerifyResult{TeeTCBSVN: make([]byte, 16), ReportDataBindingDetail: "REPORTDATA binds enclave key and nonce"}
	named := aciGatewayRaw(nonce, validSigningKey(t))
	named.UpstreamModel = "vendor/model"
	wrong := aciGatewayRaw(nonce, validSigningKey(t))
	wrong.Model = "other-model"
	wrong.UpstreamModel = "vendor/model"
	for _, tc := range []struct {
		name   string
		raw    *RawAttestation
		status Status
		detail string
	}{
		{"gateway variant names no model", aciGatewayVariantRaw(t), Fail, "the attestation names no backend for the requested model"},
		{"Venice variant without upstream model", aciGatewayRaw(nonce, validSigningKey(t)), Fail, "names no backend"},
		{"Venice variant names the backend", named, Pass, `the attestation names upstream model "vendor/model" for model "test-model" (provider-asserted)`},
		{"Venice variant names another model", wrong, Fail, `names model "other-model", not the requested model "test-model"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := buildACIReport(tc.raw, nonce, bound, nil)
			f := findFactor(t, report, FactorACIBackendNamed)
			if f.Status != tc.status || !strings.Contains(f.Detail, tc.detail) {
				t.Fatalf("aci_backend_named = %v %q, want %v with %q", f.Status, f.Detail, tc.status, tc.detail)
			}
			if tc.status == Fail && f.Enforced {
				t.Fatal("aci_backend_named is enforced under ACIDefaultAllowFail")
			}
		})
	}
	if !slices.Contains(ACIDefaultAllowFail, FactorACIBackendNamed) {
		t.Fatal("ACIDefaultAllowFail does not allow aci_backend_named to fail")
	}
	report := BuildReport(&ReportInput{
		Provider: "venice", Model: "m", Nonce: nonce, AllowFail: DefaultAllowFail,
		Raw: &RawAttestation{BackendFormat: FormatDstack, Model: "m", Nonce: nonce.Hex()},
	})
	if f := findFactor(t, report, FactorACIBackendNamed); f.Status != NotApplicable {
		t.Fatalf("aci_backend_named = %v for a dstack response, want NotApplicable", f.Status)
	}
}
