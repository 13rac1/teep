package aci_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/venice"
)

// The gateway variant test vector is the attestation body of a live Phala
// Cloud capture: its client nonce and capture time.
const (
	gatewayVariantNonce = "389ff5f5e132277769e358d0d117e6be703c996b03b55875b5e8700b80013d58"
	gatewayVariantTime  = "2026-10-27T00:08:37Z"
)

// A full report of the gateway variant body, built from the production
// parser, the offline TDX verification of the gateway quote, the gateway
// REPORTDATA verifier, the NVIDIA payload verification and the keyset
// verification with the gateway pins.
func TestBuildReportGatewayVariantBody(t *testing.T) {
	body, err := os.ReadFile("testdata/gateway_variant.json")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	nonce, err := attestation.ParseNonce(gatewayVariantNonce)
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, gatewayVariantTime)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := aci.Parse(ctx, body, "phalacloud")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	gatewayTDX := attestation.VerifyTDXQuoteOffline(ctx, raw.GatewayIntelQuote, at)
	if gatewayTDX.ParseErr != nil || gatewayTDX.SignatureErr != nil || gatewayTDX.CertChainErr != nil {
		t.Fatalf("gateway quote: parse=%v signature=%v chain=%v", gatewayTDX.ParseErr, gatewayTDX.SignatureErr, gatewayTDX.CertChainErr)
	}
	detail, rdErr := venice.ReportDataVerifier{}.VerifyReportData(gatewayTDX.ReportData, raw, nonce)
	gatewayTDX.ReportDataBindingDetail, gatewayTDX.ReportDataBindingErr = detail, rdErr
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:              "phalacloud",
		Model:                 "qwen/qwen3.8-27b",
		Raw:                   raw,
		Nonce:                 nonce,
		AllowFail:             attestation.ACIDefaultAllowFail,
		GatewayTDX:            gatewayTDX,
		GatewayNonceHex:       raw.GatewayNonceHex,
		GatewayNonce:          nonce,
		Nvidia:                attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce),
		ACIKeyset:             aci.VerifyKeyset(raw, at, aci.GatewayPins()),
		E2EEKeyBoundByGateway: true,
	})

	for _, tc := range []struct {
		name   string
		status attestation.Status
		detail string
	}{
		{attestation.FactorNonceMatch, attestation.Pass, "no echoed nonce; the gateway quote REPORTDATA and the GPU evidence bind the client nonce"},
		{attestation.FactorGWNonceMatch, attestation.Pass, "no echoed nonce; the gateway quote REPORTDATA and the GPU evidence bind the client nonce"},
		{attestation.FactorGWReportData, attestation.Pass, "REPORTDATA binds enclave key"},
		{attestation.FactorACIKeyCustody, attestation.Pass, "e2ee key custody chain verified to accepted KMS root"},
		{attestation.FactorACIBackendNamed, attestation.Fail, "the attestation binds no backend for the requested model"},
		{attestation.FactorResponseSchema, attestation.Pass, ""},
	} {
		var found bool
		for _, f := range report.Factors {
			if f.Name != tc.name {
				continue
			}
			found = true
			if f.Status != tc.status || !strings.Contains(f.Detail, tc.detail) {
				t.Errorf("%s = %v %q, want %v with %q", tc.name, f.Status, f.Detail, tc.status, tc.detail)
			}
		}
		if !found {
			t.Errorf("factor %s missing from the report", tc.name)
		}
	}
}
