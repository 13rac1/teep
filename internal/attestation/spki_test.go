package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"sync"
	"testing"
	"time"
)

// selfSignedCertDER generates a self-signed certificate and returns its DER bytes.
func selfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestComputeSPKIHash(t *testing.T) {
	der := selfSignedCertDER(t)

	hash, err := ComputeSPKIHash(der)
	if err != nil {
		t.Fatalf("ComputeSPKIHash: %v", err)
	}

	// Verify by computing independently.
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	expected := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	expectedHex := hex.EncodeToString(expected[:])

	if hash != expectedHex {
		t.Errorf("ComputeSPKIHash = %q, want %q", hash, expectedHex)
	}

	// 64 hex chars = 32 bytes SHA-256.
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestComputeSPKIHash_InvalidDER(t *testing.T) {
	_, err := ComputeSPKIHash([]byte("not a cert"))
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestSPKICache_ContainsAdd(t *testing.T) {
	c := NewSPKICache()

	if c.Contains("example.com", "aabbccdd") {
		t.Fatal("empty cache should not contain anything")
	}

	c.Add("example.com", "aabbccdd")

	if !c.Contains("example.com", "aabbccdd") {
		t.Fatal("cache should contain added entry")
	}

	// Different domain should not match.
	if c.Contains("other.com", "aabbccdd") {
		t.Fatal("different domain should not match")
	}

	// Different hash should not match.
	if c.Contains("example.com", "11223344") {
		t.Fatal("different hash should not match")
	}

	// Multiple hashes per domain.
	c.Add("example.com", "11223344")
	if !c.Contains("example.com", "aabbccdd") {
		t.Fatal("first hash should still be present")
	}
	if !c.Contains("example.com", "11223344") {
		t.Fatal("second hash should be present")
	}
}

func TestSPKICache_ConcurrentAccess(t *testing.T) {
	c := NewSPKICache()
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hash := hex.EncodeToString([]byte{byte(i)})
			c.Add("domain.com", hash)
		}(i)
	}

	// Concurrent readers.
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hash := hex.EncodeToString([]byte{byte(i)})
			c.Contains("domain.com", hash) // must not panic
		}(i)
	}

	wg.Wait()
}
