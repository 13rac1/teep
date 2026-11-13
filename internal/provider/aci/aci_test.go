package aci

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// fixtureBody reads the attestation body of a checked-in Venice ACI/1
// capture fixture.
func fixtureBody(t *testing.T) []byte {
	t.Helper()
	matches, err := filepath.Glob("../../integration/testdata/venice_aci_*/responses/0001_api.venice.ai_api_v1_tee_attestation.body")
	if err != nil || len(matches) == 0 {
		t.Fatalf("no Venice ACI/1 fixture body (err %v)", err)
	}
	body, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestParseFixture(t *testing.T) {
	raw, err := Parse(context.Background(), fixtureBody(t), "venice")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if raw.BackendFormat != attestation.FormatACI1 || raw.GatewayIntelQuote == "" || len(raw.GatewayEventLog) == 0 {
		t.Fatalf("parsed format=%q gateway quote=%d event log=%d", raw.BackendFormat, len(raw.GatewayIntelQuote), len(raw.GatewayEventLog))
	}
	if raw.IntelQuote != "" || raw.TEEHardware != "" {
		t.Fatal("gateway evidence filled the core fields of the inference host")
	}
	result := VerifyKeyset(raw, fixtureNow, GatewayPins())
	if result == nil || result.Err != nil || !result.CustodyChainValid || !result.GatewayIdentityValid {
		t.Fatalf("VerifyKeyset with the gateway pins: %+v", result)
	}
}

// Parse names the provider in its errors, so that a caller's diagnostics
// identify the provider whose response failed.
func TestParseErrorsNameProvider(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"not JSON", `{`, "phalacloud aci/1: attestation response"},
		{"empty quote", `{"api_version":"aci/1","attestation":{"evidence":{"quote":""}}}`, "phalacloud aci/1: attestation.evidence.quote is empty"},
		{"bad event log", `{"api_version":"aci/1","attestation":{"evidence":{"quote":"00","event_log":"{"}}}`, "phalacloud aci/1: decode evidence.event_log"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(context.Background(), []byte(tc.body), "phalacloud")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLogEventLog(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)
	LogEventLog(context.Background(), []attestation.EventLogEntry{
		{IMR: 3, Event: "app-id", Digest: strings.Repeat("ab", 24)},
		{IMR: 0, Event: "short", Digest: "abcd"},
	}, "nanogpt")
	out := buf.String()
	if !strings.Contains(out, `msg="nanogpt event log" entries=2`) || !strings.Contains(out, "digest=abababababababab...") || !strings.Contains(out, "digest=abcd") {
		t.Fatalf("event log records:\n%s", out)
	}
}

// GatewayPins returns copies: a caller that changes them does not change the
// accepted identities of other callers.
func TestGatewayPinsAreCopies(t *testing.T) {
	pins := GatewayPins()
	if len(pins.KMSRoots) != 2 || len(pins.GatewayAppIDs) != 2 {
		t.Fatalf("pins = %+v, want two KMS roots and two app ids", pins)
	}
	pins.KMSRoots[0] = "changed"
	pins.GatewayAppIDs[0] = "changed"
	pins.GatewayAppIDs = append(pins.GatewayAppIDs, "added")
	again := GatewayPins()
	if again.KMSRoots[0] == "changed" || again.GatewayAppIDs[0] == "changed" || len(again.GatewayAppIDs) != 2 {
		t.Fatalf("a caller changed the shared pins: %+v", again)
	}
}

// Both deployments of the private-ai-gateway are accepted: the app id and
// KMS root of 2026-08-25 and those of 2026-11-12. A value that differs in
// its last digit is not.
func TestGatewayPinsAccepted(t *testing.T) {
	pins := GatewayPins()
	for _, id := range []string{"fdb7a14e5a6675f752e2cb69c9067a98ca402918", "89c51ab856bee41efe78c40309a4deb277a02a0f"} {
		if !hexInAllowlist(id, pins.GatewayAppIDs) {
			t.Errorf("app id %s is not accepted", id)
		}
	}
	if hexInAllowlist("89c51ab856bee41efe78c40309a4deb277a02a0e", pins.GatewayAppIDs) {
		t.Error("an app id that differs in its last digit is accepted")
	}
	for _, root := range []string{
		"0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1",
		"02a335aea3df11d46ae0a373d3f26fbd1d208572ecc87e630e618dac693b7af721",
	} {
		if !hexInAllowlist(root, pins.KMSRoots) {
			t.Errorf("KMS root %s is not accepted", root)
		}
	}
	if hexInAllowlist("02a335aea3df11d46ae0a373d3f26fbd1d208572ecc87e630e618dac693b7af720", pins.KMSRoots) {
		t.Error("a KMS root that differs in its last digit is accepted")
	}
}
