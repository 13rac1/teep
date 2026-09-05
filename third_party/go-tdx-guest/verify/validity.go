// Copyright 2026 The go-tdx-guest Authors.
// Licensed under the Apache License, Version 2.0.

package verify

import (
	"crypto/x509"
	"errors"
	"time"
)

// VerifiedValidityBound returns the earliest current-time validity bound used
// by successful quote verification with collateral and revocation checks.
// The value is unavailable after a failed or offline verification. It contains
// no historical signing-certificate or caller-chosen cache expiry.
func (o *Options) VerifiedValidityBound() (time.Time, bool) {
	if o == nil || !o.hasVerifiedValidity {
		return time.Time{}, false
	}
	return o.verifiedValidity, true
}

func (o *Options) collateralValidityBound() (time.Time, error) {
	if o.chain == nil || o.collateral == nil {
		return time.Time{}, errors.New("verified collateral validity is unavailable")
	}
	c := o.collateral
	if c.PckCrl == nil || c.RootCaCrl == nil {
		return time.Time{}, errors.New("verified CRL validity is unavailable")
	}
	bounds := []time.Time{c.PckCrl.NextUpdate, c.RootCaCrl.NextUpdate, c.TdxTcbInfo.TcbInfo.NextUpdate, c.QeIdentity.EnclaveIdentity.NextUpdate}
	certificates := []*x509.Certificate{
		o.chain.PCKCertificate, o.chain.IntermediateCertificate, o.chain.RootCertificate,
		c.PckCrlIssuerIntermediateCertificate, c.PckCrlIssuerRootCertificate,
		c.TcbInfoIssuerIntermediateCertificate, c.TcbInfoIssuerRootCertificate,
		c.QeIdentityIssuerIntermediateCertificate, c.QeIdentityIssuerRootCertificate,
	}
	for _, cert := range certificates {
		if cert == nil {
			return time.Time{}, errors.New("verified certificate validity is unavailable")
		}
		bounds = append(bounds, cert.NotAfter)
	}
	var earliest time.Time
	for _, bound := range bounds {
		if bound.IsZero() {
			return time.Time{}, errors.New("verified evidence contains a zero validity bound")
		}
		if earliest.IsZero() || bound.Before(earliest) {
			earliest = bound
		}
	}
	return earliest, nil
}
