package e2ee

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict"
)

func TestNearModelKeyRetainsValidatedEncoding(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	expected := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Zero()
	if err := session.SetModelKeyEd25519(strings.ToUpper(expected)); err != nil {
		t.Fatal(err)
	}
	key := session.ModelKeyEd25519()
	// The public value is independent of ephemeral session cleanup.
	session.Zero()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if subtle.ConstantTimeCompare([]byte(key.Hex()), []byte(expected)) != 1 {
				t.Error("validated key encoding changed")
			}
		})
	}
	wg.Wait()
	if session.ModelKeyEd25519().Hex() != "" || session.ModelX25519Pub() != nil {
		t.Fatal("session retained key references after cleanup")
	}
	for _, invalid := range []string{"", "invalid", strings.Repeat("zz", 32)} {
		key, err := ParseNearModelKey(invalid)
		if err == nil || key.Hex() != "" {
			t.Fatal("invalid key produced a usable value")
		}
	}
}

func TestNearModelKeyConcurrentSessionReuse(t *testing.T) {
	models := make([]*NearCloudSession, 2)
	keys := make([]NearModelKey, 2)
	for i := range models {
		var err error
		models[i], err = NewNearCloudSession()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(models[i].Zero)
		keys[i] = testNearModelKey(t, models[i].ClientEd25519PubHex())
	}
	clients := make(chan string, 32)
	for range 2 {
		var wg sync.WaitGroup
		for i := range 16 {
			wg.Go(func() {
				index := i % len(keys)
				body, session, err := EncryptChatMessagesNearCloud([]byte(`{"model":"test","messages":[{"role":"user","content":"test"}]}`), keys[index])
				if err != nil {
					t.Error(err)
					return
				}
				defer session.Zero()
				// Pointer identity checks conversion reuse, not cryptographic equality.
				if session.ModelX25519Pub() != keys[index].x25519 {
					t.Error("session repeated model-key conversion")
				}
				clients <- session.ClientEd25519PubHex()
				var request struct {
					Messages []struct {
						Content string `json:"content"`
					} `json:"messages"`
				}
				if _, _, err := jsonstrict.Unmarshal(body, &request); err != nil || len(request.Messages) != 1 {
					t.Error("invalid encrypted request")
					return
				}
				plain, err := models[index].Decrypt(request.Messages[0].Content)
				if err != nil || string(plain) != "test" {
					t.Error("selected model could not authenticate request")
				}
				if _, err := models[1-index].Decrypt(request.Messages[0].Content); err == nil {
					t.Error("different model decrypted request")
				}
			})
		}
		wg.Wait()
	}
	close(clients)
	var previous []string
	for key := range clients {
		for _, other := range previous {
			if subtle.ConstantTimeCompare([]byte(key), []byte(other)) == 1 {
				t.Fatal("requests reused ephemeral session keys")
			}
		}
		previous = append(previous, key)
	}
	if len(previous) != 32 {
		t.Fatal("missing completed sessions")
	}
	for i, key := range keys {
		if subtle.ConstantTimeCompare([]byte(key.Hex()), []byte(models[i].ClientEd25519PubHex())) != 1 {
			t.Fatal("session cleanup changed retained model key")
		}
	}
}

func testNearModelKey(t *testing.T, text string) NearModelKey {
	t.Helper()
	key, err := ParseNearModelKey(text)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
