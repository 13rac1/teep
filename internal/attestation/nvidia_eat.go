package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/13rac1/teep/internal/jsonstrict"
)

//go:embed testdata/nvidia_device_identity_root_ca.pem
var nvidiaRootCAPEM []byte

// nvidiaRootCAFingerprint is the SHA-256 fingerprint of the NVIDIA Device
// Identity CA root certificate (DER-encoded). Used for pinning.
const nvidiaRootCAFingerprint = "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48"

// SPDM 1.1 message codes and constants.
const (
	spdmVersion11          = 0x11
	spdmGetMeasurements    = 0xe0
	spdmMeasurements       = 0x60
	spdmGetMeasurementsLen = 37
	ecdsaP384SigLen        = 96 // 48 bytes r + 48 bytes s
)

// nvidiaEAT is the JSON structure of an NVIDIA Entity Attestation Token.
type nvidiaEAT struct {
	Arch         string              `json:"arch"`
	Nonce        string              `json:"nonce"`
	EvidenceList []nvidiaGPUEvidence `json:"evidence_list"`
}

// nvidiaGPUEvidence is one GPU's attestation entry within the EAT.
type nvidiaGPUEvidence struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
}

// verifyNVIDIAEAT parses an EAT JSON payload and verifies every GPU's
// certificate chain and SPDM evidence signature. Any single GPU failure
// causes the overall result to fail.
func verifyNVIDIAEAT(payload string, expectedNonce Nonce) *NvidiaVerifyResult {
	result := &NvidiaVerifyResult{}

	var eat nvidiaEAT
	if err := jsonstrict.UnmarshalWarn([]byte(payload), &eat, "nvidia EAT"); err != nil {
		result.SignatureErr = fmt.Errorf("EAT JSON parse failed: %w", err)
		return result
	}

	if len(eat.EvidenceList) == 0 {
		result.SignatureErr = errors.New("EAT evidence_list is empty")
		return result
	}

	result.Arch = eat.Arch
	result.GPUCount = len(eat.EvidenceList)
	result.Nonce = eat.Nonce
	result.Format = "EAT"

	slog.Debug("NVIDIA EAT parsed",
		"arch", eat.Arch,
		"gpu_count", len(eat.EvidenceList),
		"eat_nonce", eat.Nonce,
		"expected_nonce", expectedNonce.Hex(),
		"eat_nonce_matches", subtle.ConstantTimeCompare([]byte(eat.Nonce), []byte(expectedNonce.Hex())) == 1,
	)

	// Check top-level nonce.
	if subtle.ConstantTimeCompare([]byte(eat.Nonce), []byte(expectedNonce.Hex())) != 1 {
		result.ClaimsErr = fmt.Errorf("EAT nonce mismatch: got %q, want %q", eat.Nonce, expectedNonce.Hex())
		return result
	}

	// Load pinned root CA.
	rootCA, err := loadPinnedNVIDIARootCA()
	if err != nil {
		result.SignatureErr = fmt.Errorf("load pinned NVIDIA root CA: %w", err)
		return result
	}

	// Verify each GPU's evidence.
	for i, ev := range eat.EvidenceList {
		if err := verifyGPUEvidence(ev, expectedNonce, rootCA); err != nil {
			result.SignatureErr = fmt.Errorf("GPU %d verification failed: %w", i, err)
			return result
		}
	}

	slog.Debug("NVIDIA EAT verification complete", "gpu_count", len(eat.EvidenceList), "arch", eat.Arch)
	return result
}

// loadPinnedNVIDIARootCA loads the embedded NVIDIA root CA certificate and
// verifies its SHA-256 fingerprint matches the pinned value.
func loadPinnedNVIDIARootCA() (*x509.Certificate, error) {
	block, _ := pem.Decode(nvidiaRootCAPEM)
	if block == nil {
		return nil, errors.New("no PEM block found in embedded NVIDIA root CA")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse NVIDIA root CA: %w", err)
	}

	// Verify fingerprint using constant-time comparison to prevent timing
	// side-channels on the pinned root CA value (F-36).
	fingerprint := sha256.Sum256(block.Bytes)
	fpHex := hex.EncodeToString(fingerprint[:])
	if subtle.ConstantTimeCompare([]byte(fpHex), []byte(nvidiaRootCAFingerprint)) != 1 {
		return nil, fmt.Errorf("NVIDIA root CA fingerprint mismatch: got %s, want %s", fpHex, nvidiaRootCAFingerprint)
	}

	return cert, nil
}

// verifyGPUEvidence verifies a single GPU's certificate chain and SPDM
// measurement signature.
func verifyGPUEvidence(ev nvidiaGPUEvidence, expectedNonce Nonce, rootCA *x509.Certificate) error {
	// 1. Parse certificate chain.
	certs, err := parseCertChain(ev.Certificate)
	if err != nil {
		return fmt.Errorf("parse cert chain: %w", err)
	}
	if len(certs) < 2 {
		return fmt.Errorf("cert chain too short: %d certs, need at least 2", len(certs))
	}

	// 2. Verify the chain terminates at the pinned root.
	if err := verifyCertChain(certs, rootCA); err != nil {
		return fmt.Errorf("cert chain verification: %w", err)
	}

	// 3. Extract leaf cert's ECDSA P-384 public key.
	leaf := certs[0]
	ecdsaKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("leaf cert public key is %T, expected *ecdsa.PublicKey", leaf.PublicKey)
	}
	if ecdsaKey.Curve != elliptic.P384() {
		return fmt.Errorf("leaf cert key curve is %s, expected P-384", ecdsaKey.Curve.Params().Name)
	}

	// 4. Decode and parse SPDM evidence.
	evidenceBytes, err := base64.StdEncoding.DecodeString(ev.Evidence)
	if err != nil {
		return fmt.Errorf("base64 decode evidence: %w", err)
	}

	if err := verifySPDMEvidence(evidenceBytes, expectedNonce, ecdsaKey); err != nil {
		return fmt.Errorf("SPDM evidence: %w", err)
	}

	return nil
}

// parseCertChain decodes a base64-encoded PEM bundle into a slice of x509
// certificates, ordered as they appear in the PEM (leaf first).
func parseCertChain(b64PEM string) ([]*x509.Certificate, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(b64PEM)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in PEM bundle")
	}
	return certs, nil
}

// verifyCertChain verifies that certs[0] (leaf) chains to pinnedRoot via the
// intermediate certs[1:n-1]. The chain's root (certs[n-1]) must match
// pinnedRoot by fingerprint.
func verifyCertChain(certs []*x509.Certificate, pinnedRoot *x509.Certificate) error {
	// The last cert in the chain should be the root. Verify it matches our pin.
	chainRoot := certs[len(certs)-1]
	chainRootFP := sha256.Sum256(chainRoot.Raw)
	pinnedRootFP := sha256.Sum256(pinnedRoot.Raw)
	if chainRootFP != pinnedRootFP {
		return fmt.Errorf("chain root CA fingerprint %s does not match pinned root %s",
			hex.EncodeToString(chainRootFP[:]), hex.EncodeToString(pinnedRootFP[:]))
	}

	// Build verification using Go's x509 library.
	rootPool := x509.NewCertPool()
	rootPool.AddCert(pinnedRoot)

	intermediatePool := x509.NewCertPool()
	for _, c := range certs[1 : len(certs)-1] {
		intermediatePool.AddCert(c)
	}

	// NVIDIA device certs don't expire (notAfter=9999-12-31) and don't
	// have standard key usages set, so we disable time and usage checks.
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("x509 chain verify: %w", err)
	}

	return nil
}

// verifySPDMEvidence validates the SPDM 1.1 GET_MEASUREMENTS request/response
// binary blob: checks version codes, extracts and verifies the nonce, and
// verifies the ECDSA P-384 signature over the message.
func verifySPDMEvidence(evidence []byte, expectedNonce Nonce, leafKey *ecdsa.PublicKey) error {
	if len(evidence) < spdmGetMeasurementsLen+10 {
		return fmt.Errorf("evidence too short: %d bytes", len(evidence))
	}

	// --- Validate GET_MEASUREMENTS request (first 37 bytes) ---
	if evidence[0] != spdmVersion11 {
		return fmt.Errorf("request SPDM version 0x%02x, expected 0x%02x", evidence[0], spdmVersion11)
	}
	if evidence[1] != spdmGetMeasurements {
		return fmt.Errorf("request code 0x%02x, expected 0x%02x (GET_MEASUREMENTS)", evidence[1], spdmGetMeasurements)
	}

	// Extract requester nonce from request[4:36].
	var requestNonce [32]byte
	copy(requestNonce[:], evidence[4:36])
	gotHex := hex.EncodeToString(requestNonce[:])
	wantHex := expectedNonce.Hex()
	slog.Debug("SPDM requester nonce extracted",
		"spdm_nonce", gotHex,
		"expected_nonce", wantHex,
		"match", subtle.ConstantTimeCompare(requestNonce[:], expectedNonce[:]) == 1,
	)
	if subtle.ConstantTimeCompare(requestNonce[:], expectedNonce[:]) != 1 {
		return fmt.Errorf("requester nonce mismatch: got %s, want %s",
			gotHex, wantHex)
	}

	// --- Validate MEASUREMENTS response (bytes 37+) ---
	resp := evidence[spdmGetMeasurementsLen:]
	if resp[0] != spdmVersion11 {
		return fmt.Errorf("response SPDM version 0x%02x, expected 0x%02x", resp[0], spdmVersion11)
	}
	if resp[1] != spdmMeasurements {
		return fmt.Errorf("response code 0x%02x, expected 0x%02x (MEASUREMENTS)", resp[1], spdmMeasurements)
	}

	// Parse variable-length fields to find the signature.
	// Response layout after header (4 bytes):
	//   [4]     NumberOfBlocks (1 byte)
	//   [5:8]   MeasurementRecordLength (3 bytes LE)
	//   [8:8+N] MeasurementRecord
	//   [+32]   Responder nonce
	//   [+2]    OpaqueDataLength (2 bytes LE)
	//   [+M]    OpaqueData
	//   [+96]   Signature (ECDSA P-384 r||s)
	if len(resp) < 8 {
		return fmt.Errorf("response too short for header: %d bytes", len(resp))
	}

	measRecordLen := int(resp[5]) | int(resp[6])<<8 | int(resp[7])<<16
	offset := 8 + measRecordLen

	// Responder nonce (32 bytes)
	if offset+32 > len(resp) {
		return fmt.Errorf("response too short for responder nonce at offset %d", offset)
	}
	offset += 32

	// OpaqueDataLength (2 bytes LE)
	if offset+2 > len(resp) {
		return fmt.Errorf("response too short for opaque length at offset %d", offset)
	}
	opaqueLen := int(binary.LittleEndian.Uint16(resp[offset : offset+2]))
	offset += 2

	// OpaqueData
	if offset+opaqueLen > len(resp) {
		return fmt.Errorf("response too short for opaque data: need %d at offset %d, have %d", opaqueLen, offset, len(resp))
	}
	offset += opaqueLen

	// Signature (96 bytes)
	if offset+ecdsaP384SigLen > len(resp) {
		return fmt.Errorf("response too short for signature: need %d at offset %d, have %d", ecdsaP384SigLen, offset, len(resp))
	}
	sigBytes := resp[offset : offset+ecdsaP384SigLen]

	// The signed message is: request || response_without_signature
	signedMsg := evidence[:spdmGetMeasurementsLen+offset]

	// Hash with SHA-384 (matching the P-384 key).
	hash := sha512.Sum384(signedMsg)

	// Parse raw r||s signature.
	r := new(big.Int).SetBytes(sigBytes[:48])
	s := new(big.Int).SetBytes(sigBytes[48:])

	if !ecdsa.Verify(leafKey, hash[:], r, s) {
		return errors.New("ECDSA P-384 signature verification failed")
	}

	slog.Debug("SPDM evidence verified",
		"meas_record_len", measRecordLen,
		"opaque_len", opaqueLen,
		"evidence_len", len(evidence))

	return nil
}
