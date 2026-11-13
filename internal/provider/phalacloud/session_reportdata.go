package phalacloud

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"golang.org/x/crypto/sha3"
)

// phalaDirectReportData verifies the REPORTDATA of a phala-direct upstream:
//
//	REPORTDATA[0:32]  = sha256(signing_address || tls_cert_fingerprint)
//	REPORTDATA[32:64] = nonce
//
// signing_address is the 20-byte keccak256 address of the uncompressed
// secp256k1 signing key, so the quote binds the signing key, the TLS key
// and the nonce. The layout is the NEAR-direct one with an ecdsa address.
type phalaDirectReportData struct{}

func (phalaDirectReportData) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	if raw.SigningAlgo != "ecdsa" {
		return "", fmt.Errorf("signing_algo is %q, want ecdsa", raw.SigningAlgo)
	}
	key, err := hex.DecodeString(raw.SigningKey)
	if err != nil || len(key) != 65 || key[0] != 0x04 {
		return "", errors.New("signing key is not an uncompressed secp256k1 point")
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(key[1:])
	derived := h.Sum(nil)[12:]
	address, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(raw.SigningAddress), "0x"))
	if err != nil || len(address) != 20 {
		return "", errors.New("signing_address is not a 20-byte hex address")
	}
	if subtle.ConstantTimeCompare(derived, address) != 1 {
		return "", errors.New("signing_address is not the keccak256 address of the signing key")
	}
	fingerprint, err := hex.DecodeString(raw.TLSFingerprint)
	if err != nil || len(fingerprint) != sha256.Size {
		return "", errors.New("tls_cert_fingerprint is not a 32-byte hex fingerprint")
	}
	expected := sha256.Sum256(append(address, fingerprint...))
	if subtle.ConstantTimeCompare(expected[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected sha256(signing_address + tls_cert_fingerprint) = %s",
			hex.EncodeToString(reportData[:32]), hex.EncodeToString(expected[:]))
	}
	if subtle.ConstantTimeCompare(nonce[:], reportData[32:64]) != 1 {
		return "", errors.New("REPORTDATA[32:64] is not the nonce of the evidence request")
	}
	return "REPORTDATA binds sha256(signing_address + tls_cert_fingerprint) and the gateway's request nonce", nil
}
