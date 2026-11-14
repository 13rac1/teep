package tlsct_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	cttls "github.com/google/certificate-transparency-go/tls"
)

func TestCheckTLSState_LogCollections(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cert := server.Certificate()
	sct, key := signedHandshakeSCT(t, cert)

	for _, tiled := range []bool{false, true} {
		name := "RFC6962"
		if tiled {
			name = "tiled"
		}
		t.Run(name, func(t *testing.T) {
			for _, outcome := range []string{"valid", "invalid signature", "unknown log", "invalid key"} {
				t.Run(outcome, func(t *testing.T) {
					candidate := sct
					logKey := key
					logID := sct.LogID.KeyID
					switch outcome {
					case "invalid signature":
						candidate.Timestamp++
					case "unknown log":
						logID[0] ^= 1
					case "invalid key":
						logKey = []byte("invalid public key")
					}
					op := &loglist3.Operator{}
					if tiled {
						op.TiledLogs = []*loglist3.TiledLog{{LogID: logID[:], Key: logKey}}
					} else {
						op.Logs = []*loglist3.Log{{LogID: logID[:], Key: logKey}}
					}
					checker := tlsct.NewChecker()
					checker.InjectLogList(&loglist3.LogList{Operators: []*loglist3.Operator{op}})
					raw, err := cttls.Marshal(candidate)
					if err != nil {
						t.Fatal(err)
					}
					state := &tls.ConnectionState{
						PeerCertificates:            []*x509.Certificate{cert},
						SignedCertificateTimestamps: [][]byte{raw},
					}
					var wg sync.WaitGroup
					for range 8 {
						wg.Go(func() {
							err := checker.CheckTLSState(context.Background(), "example.com", state)
							if (err == nil) != (outcome == "valid") {
								t.Errorf("CT verification: %v; expected %s", err, outcome)
							}
						})
					}
					wg.Wait()
				})
			}
		})
	}
}

func signedHandshakeSCT(t *testing.T, cert *x509.Certificate) (sct ct.SignedCertificateTimestamp, publicKey []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sct = ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: sha256.Sum256(pub)},
		Timestamp:  uint64(time.Now().UnixMilli()),
	}
	leaf, err := ct.MerkleTreeLeafFromRawChain([]ct.ASN1Cert{{Data: cert.Raw}}, ct.X509LogEntryType, sct.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: *leaf})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sct.Signature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA},
		Signature: sig,
	}
	return sct, pub
}
