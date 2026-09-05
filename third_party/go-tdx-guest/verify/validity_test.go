package verify

import (
	"context"
	"testing"
	"time"

	testcases "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/testing/testdata"
)

func TestVerifiedValidityUnavailable(t *testing.T) {
	var absent *Options
	if _, ok := absent.VerifiedValidityBound(); ok {
		t.Fatal("nil options supplied validity")
	}
	options := &Options{Now: testTimeSet(currentTime), verifiedValidity: currentTime, hasVerifiedValidity: true}
	if err := RawTdxQuoteContext(context.Background(), testdata.RawQuote, options); err != nil {
		t.Fatal(err)
	}
	if _, ok := options.VerifiedValidityBound(); ok {
		t.Fatal("offline verification supplied validity")
	}
	options.verifiedValidity, options.hasVerifiedValidity = currentTime, true
	if err := TdxQuoteContext(context.Background(), nil, options); err == nil {
		t.Fatal("invalid quote accepted")
	}
	if _, ok := options.VerifiedValidityBound(); ok {
		t.Fatal("failed verification retained validity")
	}
	options.verifiedValidity, options.hasVerifiedValidity = currentTime, true
	if err := RawTdxQuoteContext(context.Background(), nil, options); err == nil {
		t.Fatal("malformed raw quote accepted")
	}
	if _, ok := options.VerifiedValidityBound(); ok {
		t.Fatal("raw parsing failure retained validity")
	}
}

func TestCollateralValidityMinimum(t *testing.T) {
	options := &Options{GetCollateral: true, CheckRevocations: true, Getter: testcases.TestGetter, Now: testTimeSet(currentTime)}
	collateral, err := obtainCollateral(context.Background(), "50806f000000", platformIssuerID, options)
	if err != nil {
		t.Fatal(err)
	}
	options.collateral = collateral
	if err := verifyCollateral(options); err != nil {
		t.Fatal(err)
	}
	options.chain = &PCKCertificateChain{PCKCertificate: collateral.PckCrlIssuerIntermediateCertificate, IntermediateCertificate: collateral.PckCrlIssuerIntermediateCertificate, RootCertificate: collateral.PckCrlIssuerRootCertificate}
	bound, err := options.collateralValidityBound()
	if err != nil || bound.IsZero() {
		t.Fatalf("validity: %v, %v", bound, err)
	}
	early := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	collateral.RootCaCrl.NextUpdate = early
	bound, err = options.collateralValidityBound()
	if err != nil || !bound.Equal(early) {
		t.Fatalf("earliest CRL: %v, %v", bound, err)
	}
	collateral.RootCaCrl.NextUpdate = time.Time{}
	if _, err := options.collateralValidityBound(); err == nil {
		t.Fatal("zero bound accepted")
	}
	if _, ok := options.VerifiedValidityBound(); ok {
		t.Fatal("parsing collateral alone supplied authenticated validity")
	}
}
