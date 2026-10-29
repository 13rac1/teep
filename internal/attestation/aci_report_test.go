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
	raw.ACIGatewayVariant = true
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

// boundGatewayTDX is a gateway TDX result whose signature, certificate chain
// and REPORTDATA binding verified.
func boundGatewayTDX() *TDXVerifyResult {
	return &TDXVerifyResult{TeeTCBSVN: make([]byte, 16), ReportDataBindingDetail: "REPORTDATA binds enclave key and nonce"}
}

// A gateway-variant ACI/1 response carries no echoed nonce; its report
// evaluates the client nonce where the evidence binds it: the verified
// gateway REPORTDATA, and the GPU evidence when it carries a nonce.
func TestBuildReport_ACINonceWithoutEcho(t *testing.T) {
	nonce := NewNonce()
	unbound := boundGatewayTDX()
	unbound.ReportDataBindingErr = errors.New("REPORTDATA[32:64] mismatch")
	unsigned := boundGatewayTDX()
	unsigned.SignatureErr = errors.New("quote signature invalid")
	unchained := boundGatewayTDX()
	unchained.CertChainErr = errors.New("PCK chain invalid")
	other := NewNonce()
	for _, tc := range []struct {
		name       string
		gatewayTDX *TDXVerifyResult
		nvidia     *NvidiaVerifyResult
		status     Status
		detail     string
	}{
		{"REPORTDATA only", boundGatewayTDX(), nil, Pass, "the gateway quote REPORTDATA binds the client nonce (no GPU evidence nonce)"},
		{"REPORTDATA and GPU evidence", boundGatewayTDX(), &NvidiaVerifyResult{Nonce: nonce.Hex()}, Pass, "the gateway quote REPORTDATA and the GPU evidence bind the client nonce"},
		{"GPU evidence nonce differs", boundGatewayTDX(), &NvidiaVerifyResult{Nonce: other.Hex()}, Fail, "is not the client nonce"},
		{"REPORTDATA binding failed", unbound, &NvidiaVerifyResult{Nonce: nonce.Hex()}, Fail, "REPORTDATA binding of the client nonce did not verify"},
		{"quote signature failed", unsigned, nil, Fail, "REPORTDATA binding of the client nonce did not verify"},
		{"certificate chain failed", unchained, nil, Fail, "REPORTDATA binding of the client nonce did not verify"},
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

// A Venice-variant ACI/1 response defines an echoed nonce; one without it
// fails both nonce factors, as before the gateway variant existed.
func TestBuildReport_ACIVeniceVariantMissingEchoFails(t *testing.T) {
	nonce := NewNonce()
	raw := aciGatewayRaw(nonce, validSigningKey(t))
	raw.Nonce = ""
	raw.GatewayNonceHex = ""
	report := buildACIReport(raw, nonce, boundGatewayTDX(), &NvidiaVerifyResult{Nonce: nonce.Hex()})
	if f := findFactor(t, report, FactorNonceMatch); f.Status != Fail || !strings.Contains(f.Detail, "nonce field absent") {
		t.Errorf("nonce_match = %v %q, want Fail for a missing Venice echo", f.Status, f.Detail)
	}
	if f := findFactor(t, report, FactorGWNonceMatch); f.Status != Fail || !strings.Contains(f.Detail, "request_nonce absent") {
		t.Errorf("gateway_nonce_match = %v %q, want Fail for a missing Venice echo", f.Status, f.Detail)
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

// aci_backend_named passes only when attested evidence binds a backend for
// the requested model, which no ACI/1 evidence does, so it fails; the detail
// names provider-asserted fields when present. It is allowed to fail by
// default for ACI/1 and not applicable to other formats.
func TestBuildReport_ACIBackendNamed(t *testing.T) {
	nonce := NewNonce()
	named := aciGatewayRaw(nonce, validSigningKey(t))
	named.UpstreamModel = "vendor/model"
	for _, tc := range []struct {
		name   string
		raw    *RawAttestation
		detail string
	}{
		{"gateway variant", aciGatewayVariantRaw(t), "the attestation binds no backend for the requested model"},
		{"Venice variant with provider-asserted fields", named, `the attestation binds no backend for the requested model; the response names model "test-model" / upstream "vendor/model", provider-asserted`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := buildACIReport(tc.raw, nonce, boundGatewayTDX(), nil)
			f := findFactor(t, report, FactorACIBackendNamed)
			if f.Status != Fail || f.Detail != tc.detail {
				t.Fatalf("aci_backend_named = %v %q, want Fail %q", f.Status, f.Detail, tc.detail)
			}
			if f.Enforced {
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
