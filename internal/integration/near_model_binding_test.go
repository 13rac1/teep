package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"regexp"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestNearSignedModelKeySubstitution(t *testing.T) {
	for _, name := range []string{"neardirect", "nearcloud"} {
		t.Run(name, func(t *testing.T) { testNearSignedModelKeySubstitution(t, name) })
	}
}

func testNearSignedModelKeySubstitution(t *testing.T, name string) {
	t.Helper()
	ctx := context.Background()
	env := loadFixture(t, name)
	var raw *attestation.RawAttestation
	var err error
	if name == "neardirect" {
		route, routeErr := provider.NewResolvedRoute("https://"+env.manifest.NearRoute.Authority, "")
		if routeErr != nil {
			t.Fatal(routeErr)
		}
		attester := neardirect.NewAttester(env.manifest.NearConfig.Origin, "", true)
		attester.SetClientFactory(func() *http.Client { return &http.Client{Transport: env.client.Transport} })
		attester.SetMetadataClient(env.client)
		raw, err = attester.FetchAttestationForRoute(ctx, route, env.manifest.Model, env.nonce)
	} else {
		attester := nearcloud.NewAttester("", true)
		attester.SetClient(env.client)
		raw, err = attester.FetchAttestation(ctx, env.manifest.Model, env.nonce)
	}
	if err != nil {
		t.Fatal(err)
	}
	tdx := attestation.VerifyTDXQuoteOnline(ctx, raw.IntelQuote, attestation.NewCollateralGetter(env.client), fixtureVerificationTime(&env))
	if tdx.ParseErr != nil || tdx.SignatureErr != nil || tdx.CertChainErr != nil {
		t.Fatalf("signed quote verification failed: parse=%v signature=%v chain=%v", tdx.ParseErr, tdx.SignatureErr, tdx.CertChainErr)
	}
	verifier := neardirect.ReportDataVerifier{}
	if _, err := verifier.VerifyReportData(tdx.ReportData, raw, env.nonce); err != nil {
		t.Fatalf("original binding: %v", err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	keyHex := hex.EncodeToString(key)
	// Change every repeated public-key field without changing signed evidence
	// or the address. Agreement between representations cannot authenticate it.
	field := regexp.MustCompile(`("signing_public_key"\s*:\s*")[^"]*(")`)
	body := field.ReplaceAll(raw.RawBody, []byte(`${1}`+keyHex+`${2}`))
	var changed *attestation.RawAttestation
	if name == "neardirect" {
		changed, err = neardirect.ParseAttestationResponse(ctx, body, env.manifest.Model)
	} else {
		_, changed, err = nearcloud.ParseGatewayResponse(ctx, body, env.manifest.Model)
	}
	if err != nil {
		t.Fatalf("parse substituted response: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(changed.SigningKey), []byte(keyHex)) != 1 ||
		subtle.ConstantTimeCompare([]byte(raw.SigningKey), []byte(changed.SigningKey)) == 1 {
		t.Fatal("public key substitution did not occur")
	}
	for _, pair := range [][2]string{{raw.IntelQuote, changed.IntelQuote}, {raw.SigningAddress, changed.SigningAddress}, {raw.TLSFingerprint, changed.TLSFingerprint}, {raw.Nonce, changed.Nonce}} {
		if subtle.ConstantTimeCompare([]byte(pair[0]), []byte(pair[1])) != 1 {
			t.Fatal("substitution changed retained evidence")
		}
	}
	if _, err := verifier.VerifyReportData(tdx.ReportData, changed, env.nonce); err == nil {
		t.Fatal("signed quote authenticated a substituted model key")
	}
}
