package aci_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
)

// The canonical report test vector is the body of a live request to
// /v1/aci/attestation on tee.redpill.ai, with its client nonce and time.
const (
	canonicalNonce = "8e71d47d00a62b329b43b78eb08d196f0084f600e2e20710a7937c9a98e46d65"
	canonicalTime  = "2026-10-30T07:05:52Z"
)

func canonicalBody(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/canonical_report.json")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// mutateCanonical decodes the report, applies change and encodes it again.
func mutateCanonical(t *testing.T, change func(top map[string]any)) []byte {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(canonicalBody(t), &top); err != nil {
		t.Fatal(err)
	}
	change(top)
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseCanonical(t *testing.T) {
	raw, err := aci.ParseCanonical(context.Background(), canonicalBody(t), "phalacloud")
	if err != nil {
		t.Fatalf("ParseCanonical: %v", err)
	}
	if !raw.ACICanonicalReport || raw.ACIGatewayVariant || raw.BackendFormat != attestation.FormatACI1 {
		t.Errorf("canonical=%v gateway=%v format=%q", raw.ACICanonicalReport, raw.ACIGatewayVariant, raw.BackendFormat)
	}
	if len(raw.SigningKey) != 130 || !strings.HasPrefix(raw.SigningKey, "04") || raw.GatewayIntelQuote == "" || raw.Nonce != "" {
		t.Errorf("signing key %q, quote %d, nonce %q", raw.SigningKey, len(raw.GatewayIntelQuote), raw.Nonce)
	}
	if len(raw.UnknownFields) != 0 || len(raw.MissingFields) != 0 {
		t.Errorf("unknown %v missing %v", raw.UnknownFields, raw.MissingFields)
	}
}

func attestationMap(top map[string]any) map[string]any { return top["attestation"].(map[string]any) }

func keysetMap(top map[string]any) map[string]any {
	return attestationMap(top)["workload_keyset"].(map[string]any)
}

// Every member that §4.1 does not define, every absent member, and every
// keyset without exactly one secp256k1 E2EE v2 key fails the parse.
func TestParseCanonicalRefusesMalformedReports(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(top map[string]any)
		want   string
	}{
		{"undefined top-level field", func(top map[string]any) { top["nonce"] = "00" }, "undefined fields"},
		{"undefined nested field", func(top map[string]any) { attestationMap(top)["extra"] = 1 }, "undefined fields"},
		{"absent report_data", func(top map[string]any) { delete(attestationMap(top), "report_data") }, "lacks fields"},
		{"absent service_capabilities", func(top map[string]any) { delete(top, "service_capabilities") }, "lacks fields"},
		{"other api_version", func(top map[string]any) { top["api_version"] = "aci/2" }, "api_version"},
		{"no secp256k1 key", func(top map[string]any) {
			keys := keysetMap(top)["e2ee_public_keys"].([]any)
			keysetMap(top)["e2ee_public_keys"] = []any{keys[1]}
		}, "no uncompressed"},
		{"two secp256k1 keys", func(top map[string]any) {
			keys := keysetMap(top)["e2ee_public_keys"].([]any)
			keysetMap(top)["e2ee_public_keys"] = append(keys, keys[0])
		}, "more than one"},
		{"empty quote", func(top map[string]any) {
			attestationMap(top)["evidence"].(map[string]any)["quote"] = ""
		}, "quote is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := aci.ParseCanonical(context.Background(), mutateCanonical(t, tc.change), "phalacloud")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	dup := append([]byte(`{"api_version":"aci/1",`), canonicalBody(t)[1:]...)
	if _, err := aci.ParseCanonical(context.Background(), dup, "phalacloud"); err == nil {
		t.Error("duplicate member accepted")
	}
}

// The statement verifier accepts the live quote with its client nonce, and
// fails another nonce, a keyset that does not hash to the declared digest,
// and a report that is not canonical.
func TestStatementReportDataVerifier(t *testing.T) {
	ctx := context.Background()
	at, err := time.Parse(time.RFC3339, canonicalTime)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := attestation.ParseNonce(canonicalNonce)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := aci.ParseCanonical(ctx, canonicalBody(t), "phalacloud")
	if err != nil {
		t.Fatal(err)
	}
	quote := attestation.VerifyTDXQuoteOffline(ctx, raw.GatewayIntelQuote, at)
	if quote.ParseErr != nil || quote.SignatureErr != nil || quote.CertChainErr != nil {
		t.Fatalf("quote: parse=%v signature=%v chain=%v", quote.ParseErr, quote.SignatureErr, quote.CertChainErr)
	}
	v := aci.StatementReportDataVerifier{}
	detail, err := v.VerifyReportData(quote.ReportData, raw, nonce)
	if err != nil || !strings.Contains(detail, "binds the keyset digest") {
		t.Fatalf("VerifyReportData = %q, %v", detail, err)
	}
	if _, err := v.VerifyReportData(quote.ReportData, raw, attestation.NewNonce()); err == nil {
		t.Error("another nonce passed")
	}
	tampered, err := aci.ParseCanonical(ctx, mutateCanonical(t, func(top map[string]any) {
		keysetMap(top)["subject"] = "app-id:0x00"
	}), "phalacloud")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyReportData(quote.ReportData, tampered, nonce); err == nil || !strings.Contains(err.Error(), "is not the digest of the keyset") {
		t.Errorf("changed keyset: err = %v", err)
	}
	gateway, err := aci.Parse(ctx, func() []byte {
		b, err := os.ReadFile("testdata/gateway_variant.json")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}(), "phalacloud")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyReportData(quote.ReportData, gateway, nonce); err == nil {
		t.Error("a report of the compatibility route passed the statement verifier")
	}
}

// A full report of the canonical body with the Phala Cloud allow_fail list:
// the statement binding and the key custody pass and are enforced; the nonce
// factors and the GPU factors do not pass and are allowed. The measurement,
// compose and event log factors need the policy inputs of verify.Run and are
// covered by the replay tests.
func TestBuildReportCanonicalBody(t *testing.T) {
	ctx := context.Background()
	at, err := time.Parse(time.RFC3339, canonicalTime)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := attestation.ParseNonce(canonicalNonce)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := aci.ParseCanonical(ctx, canonicalBody(t), "phalacloud")
	if err != nil {
		t.Fatal(err)
	}
	gatewayTDX := attestation.VerifyTDXQuoteOffline(ctx, raw.GatewayIntelQuote, at)
	gatewayTDX.ReportDataBindingDetail, gatewayTDX.ReportDataBindingErr = aci.StatementReportDataVerifier{}.VerifyReportData(gatewayTDX.ReportData, raw, nonce)
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:              "phalacloud",
		Model:                 "qwen/qwen3.8-27b",
		Raw:                   raw,
		Nonce:                 nonce,
		AllowFail:             attestation.PhalaCloudACIDefaultAllowFail,
		GatewayTDX:            gatewayTDX,
		GatewayNonceHex:       raw.GatewayNonceHex,
		GatewayNonce:          nonce,
		Nvidia:                attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce),
		ACIKeyset:             aci.VerifyKeyset(raw, at, aci.GatewayPins()),
		E2EEKeyBoundByGateway: true,
	})
	if report.ACIKeysetDigest != raw.ACIWorkloadKeysetDigest {
		t.Errorf("report keyset digest %q, want %q", report.ACIKeysetDigest, raw.ACIWorkloadKeysetDigest)
	}
	for _, tc := range []struct {
		name     string
		status   attestation.Status
		enforced bool
		detail   string
	}{
		{attestation.FactorNonceMatch, attestation.Fail, false, "no echoed nonce; freshness rests on gateway_tee_reportdata_binding"},
		{attestation.FactorGWNonceMatch, attestation.Fail, false, "no echoed nonce"},
		{attestation.FactorGWReportData, attestation.Pass, true, "binds the keyset digest"},
		{attestation.FactorACIKeyCustody, attestation.Pass, true, "e2ee key custody chain verified"},
		{attestation.FactorNvidiaSignature, attestation.Fail, false, ""},
	} {
		var found bool
		for _, f := range report.Factors {
			if f.Name != tc.name {
				continue
			}
			found = true
			if f.Status != tc.status || f.Enforced != tc.enforced || !strings.Contains(f.Detail, tc.detail) {
				t.Errorf("%s = %v enforced=%v %q, want %v enforced=%v with %q", tc.name, f.Status, f.Enforced, f.Detail, tc.status, tc.enforced, tc.detail)
			}
		}
		if !found {
			t.Errorf("factor %s missing from the report", tc.name)
		}
	}
	// The report carries no GPU evidence: the GPU nonce factor does not pass
	// and is not enforced.
	for _, f := range report.Factors {
		if f.Name == attestation.FactorNvidiaClientNonce && (f.Status == attestation.Pass || f.Enforced) {
			t.Errorf("%s = %v enforced=%v", f.Name, f.Status, f.Enforced)
		}
	}
}

// A missing X-ACI-Keyset-Digest is an error; a different one is reported,
// not an error, because a response in flight continues (ACI/1 §5.2).
func TestCheckServedKeysetDigest(t *testing.T) {
	report := &attestation.VerificationReport{ACIKeysetDigest: "sha256:aa"}
	for _, tc := range []struct {
		served  string
		differs bool
		err     bool
	}{
		{"sha256:aa", false, false},
		{"sha256:bb", true, false},
		{"", false, true},
	} {
		h := map[string][]string{}
		if tc.served != "" {
			h["X-Aci-Keyset-Digest"] = []string{tc.served}
		}
		differs, err := attestation.CheckServedKeysetDigest(h, report)
		if differs != tc.differs || (err != nil) != tc.err {
			t.Errorf("served %q: differs=%v err=%v", tc.served, differs, err)
		}
	}
	if differs, err := attestation.CheckServedKeysetDigest(nil, &attestation.VerificationReport{}); differs || err != nil {
		t.Errorf("report without a canonical digest: differs=%v err=%v", differs, err)
	}
}
