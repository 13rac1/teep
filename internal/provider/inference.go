package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/aci"
)

// InferenceInput contains request data and the key from an acquired authorization.
// Callers must authenticate the key before preparing an attempt.
type InferenceInput struct {
	Body          []byte
	SigningKey    string                    // Non-NEAR protocol key.
	BackendFormat attestation.BackendFormat // Format of the attestation that authorized SigningKey.
	ModelKey      e2ee.NearModelKey         // NEAR key from the acquired authorization.
	// ACISessionIDs are the attested sessions of the acquired authorization;
	// a Phala Cloud request pins them (aci.PinSessions).
	ACISessionIDs     []string
	Path, ContentType string
	Stream            bool
	Endpoint          e2ee.EndpointType
}

// PrepareInference uses the provider's production encryptor and preparer for
// both proxy and standalone attempts. The caller owns the returned sessions.
func PrepareInference(ctx context.Context, prov *Provider, route ResolvedRoute, input *InferenceInput) (*http.Request, e2ee.EncryptResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, e2ee.EncryptResult{}, err
	}
	if route.Authority() == "" {
		return nil, e2ee.EncryptResult{}, errors.New("inference requires a resolved route")
	}
	if prov.Name == "phalacloud" {
		// Every Phala Cloud request is served only through a verified
		// attested session; without one the request fails here.
		pinned, err := aci.PinSessions(input.Body, input.ACISessionIDs)
		if err != nil {
			return nil, e2ee.EncryptResult{}, err
		}
		in := *input
		in.Body = pinned
		input = &in
	}
	encrypted := e2ee.EncryptResult{Body: input.Body}
	if prov.E2EE {
		if prov.Encryptor == nil {
			return nil, e2ee.EncryptResult{}, errors.New("inference requires an encryptor")
		}
		var err error
		encrypted, err = encryptInference(prov, input)
		if err != nil {
			return nil, e2ee.EncryptResult{}, err
		}
	}
	req, err := prepareInferenceRequest(ctx, prov, route, input, encrypted)
	if err != nil {
		e2ee.ZeroSessions(encrypted.Session, encrypted.Chutes, encrypted.EHBP)
		return nil, e2ee.EncryptResult{}, err
	}
	return req, encrypted, nil
}

func prepareInferenceRequest(ctx context.Context, prov *Provider, route ResolvedRoute, input *InferenceInput, encrypted e2ee.EncryptResult) (*http.Request, error) {
	var body io.Reader = bytes.NewReader(encrypted.Body)
	if encrypted.BodyReader != nil {
		body = encrypted.BodyReader
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, route.BaseURL()+input.Path, body)
	if err != nil {
		return nil, err
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", input.ContentType)
	SetUserAgent(req)
	SetEHBPHeaders(req, encrypted.EHBP)
	authenticated := PreparationData{ModelKey: input.ModelKey}
	if err := PrepareInferenceHeaders(req, prov, encrypted.Session, encrypted.Chutes, input.Stream, input.Path, authenticated); err != nil {
		return nil, err
	}
	return req, nil
}

// ReceiptRequestHash returns the sha256 that request.received of an ACI/1
// receipt must state for a prepared request: for E2EE v2, the restored
// request that the session recorded; for a request without encryption, the
// wire body, which the gateway hashes as received. It returns nil when teep
// cannot reproduce the gateway's form, or for another encryption protocol.
func ReceiptRequestHash(encrypted e2ee.EncryptResult) *[32]byte {
	if s, ok := encrypted.Session.(*e2ee.ACIv2Session); ok {
		return s.RestoredRequestHash()
	}
	if encrypted.Session != nil || encrypted.Chutes != nil || encrypted.EHBP != nil || encrypted.BodyReader != nil {
		return nil
	}
	sum := sha256.Sum256(encrypted.Body)
	return &sum
}

// encryptInference keeps NEAR requests on the validated-key interface. Missing
// typed material fails closed; it never reparses a different string key.
func encryptInference(prov *Provider, input *InferenceInput) (e2ee.EncryptResult, error) {
	if prov.Name == "nearcloud" || prov.Name == "neardirect" {
		encryptor, ok := prov.Encryptor.(interface {
			EncryptRequestWithModelKey([]byte, e2ee.NearModelKey, e2ee.EndpointType) (e2ee.EncryptResult, error)
		})
		if !ok {
			return e2ee.EncryptResult{}, errors.New("NEAR inference requires a validated-key encryptor")
		}
		return encryptor.EncryptRequestWithModelKey(input.Body, input.ModelKey, input.Endpoint)
	}
	return prov.Encryptor.EncryptRequest(input.Body, &attestation.RawAttestation{SigningKey: input.SigningKey, BackendFormat: input.BackendFormat}, input.Endpoint)
}

// SetEHBPHeaders sets EHBP headers on the upstream request.
// Connection lifetime is intentionally left to the SPKI-pinned transport,
// which may safely pool connections authenticated during their TLS handshake.
func SetEHBPHeaders(req *http.Request, ehbp *e2ee.EHBPSession) {
	if ehbp != nil {
		req.Header.Set("Ehbp-Encapsulated-Key", ehbp.EncapKeyHex())
		req.ContentLength = -1 // Let net/http select framing for the negotiated protocol.
	}
}

// PrepareInferenceHeaders injects auth and E2EE headers into the upstream request.
// It builds protocol-specific headers from the Decryptor via type switch, then
// delegates to the provider's Preparer. When no Preparer is configured, it sets
// only the Authorization header.
func PrepareInferenceHeaders(req *http.Request, prov *Provider, session e2ee.Decryptor, meta *e2ee.ChutesE2EE, stream bool, endpointPath string, authenticated PreparationData) error {
	if prov.Preparer == nil {
		if prov.Name == "nearcloud" {
			return errors.New("NearCloud requires an authenticated request preparer")
		}
		if prov.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+prov.APIKey)
		}
		return nil
	}

	// nil session: plaintext or Chutes (Chutes headers are in meta, not session).
	var e2eeHeaders http.Header
	switch s := session.(type) {
	case *e2ee.VeniceSession:
		e2eeHeaders = make(http.Header)
		e2eeHeaders.Set("X-Venice-Tee-Client-Pub-Key", s.ClientPubKeyHex())
		e2eeHeaders.Set("X-Venice-Tee-Model-Pub-Key", s.ModelKeyHex())
		e2eeHeaders.Set("X-Venice-Tee-Signing-Algo", "ecdsa")
	case *e2ee.ACIv2Session:
		e2eeHeaders = make(http.Header)
		for name, value := range s.Headers() {
			e2eeHeaders.Set(name, value)
		}
	case *e2ee.NearCloudSession:
		e2eeHeaders = make(http.Header)
		e2eeHeaders.Set("X-Signing-Algo", "ed25519")
		e2eeHeaders.Set("X-Client-Pub-Key", s.ClientEd25519PubHex())
		e2eeHeaders.Set("X-Encryption-Version", "2")
		e2eeHeaders.Set("X-Encrypt-All-Fields", "true")
	}
	return prov.Preparer.PrepareRequest(req, e2eeHeaders, meta, stream, endpointPath, authenticated)
}
