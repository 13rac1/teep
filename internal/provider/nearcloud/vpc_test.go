package nearcloud_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider/nearcloud"
)

const testVPC = `"vpc":{"vpc_server_app_id":"ab","vpc_hostname":"test.internal"},`

// A gateway response without the vpc member parses. The NEAR Cloud gateway
// omitted vpc in one live response on 2026-11-11.
func TestParseGatewayResponse_NoVPC(t *testing.T) {
	body := minimalGatewayJSON("test-model", "abc123", "sha256:fp")
	if !strings.Contains(body, testVPC) {
		t.Fatal("test fixture does not contain the vpc member")
	}
	body = strings.Replace(body, testVPC, "", 1)

	gw, raw, err := nearcloud.ParseGatewayResponse(context.Background(), []byte(body), "test-model")
	if err != nil {
		t.Fatalf("ParseGatewayResponse without vpc: %v", err)
	}
	if gw.NonceHex != "abc123" || gw.TLSCertFingerprint != "sha256:fp" {
		t.Errorf("gateway = %+v, want nonce abc123 and fingerprint sha256:fp", gw)
	}
	if len(raw.UnknownFields) != 0 {
		t.Errorf("UnknownFields = %v, want none", raw.UnknownFields)
	}
}

// A vpc member that is present keeps its strict decoding: a missing required
// member is an error, and an unknown member is returned to the caller.
func TestParseGatewayResponse_VPCPresentStrict(t *testing.T) {
	ctx := context.Background()
	base := minimalGatewayJSON("test-model", "abc123", "sha256:fp")

	missing := strings.Replace(base, testVPC, `"vpc":{"vpc_server_app_id":"ab"},`, 1)
	if _, _, err := nearcloud.ParseGatewayResponse(ctx, []byte(missing), "test-model"); err == nil {
		t.Error("vpc without vpc_hostname: want error, got nil")
	}

	null := strings.Replace(base, testVPC, `"vpc":null,`, 1)
	if _, _, err := nearcloud.ParseGatewayResponse(ctx, []byte(null), "test-model"); err == nil {
		t.Error("vpc null: want error, got nil")
	}

	extra := strings.Replace(base, testVPC,
		`"vpc":{"vpc_server_app_id":"ab","vpc_hostname":"test.internal","extra":1},`, 1)
	_, raw, err := nearcloud.ParseGatewayResponse(ctx, []byte(extra), "test-model")
	if err != nil {
		t.Fatalf("vpc with unknown member: %v", err)
	}
	if !slices.Contains(raw.UnknownFields, "nearcloud.gateway_attestation.vpc.extra") {
		t.Errorf("UnknownFields = %v, want nearcloud.gateway_attestation.vpc.extra", raw.UnknownFields)
	}
}
