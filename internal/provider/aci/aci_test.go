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
		{"not JSON", `{`, "phalacloud aci/1: unmarshal attestation response"},
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
	if len(pins.KMSRoots) != 1 || len(pins.GatewayAppIDs) != 1 {
		t.Fatalf("pins = %+v, want one KMS root and one app id", pins)
	}
	pins.KMSRoots[0] = "changed"
	pins.GatewayAppIDs = append(pins.GatewayAppIDs, "added")
	again := GatewayPins()
	if again.KMSRoots[0] == "changed" || len(again.GatewayAppIDs) != 1 {
		t.Fatalf("a caller changed the shared pins: %+v", again)
	}
}
