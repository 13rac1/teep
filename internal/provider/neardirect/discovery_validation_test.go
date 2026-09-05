package neardirect

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestDiscoveryRejectsAmbiguousMapping(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"endpoints":[]}`, `{"endpoints":[],"extra":true}`,
		`{"endpoints":[{"domain":"a.near.ai","models":[]}]}`,
		`{"endpoints":[{"domain":"a.near.ai","models":[""]}]}`,
		`{"endpoints":[{"domain":"a.near.ai","models":["m","m"]}]}`,
		`{"endpoints":[{"domain":"a.near.ai","models":["m"]},{"domain":"b.near.ai","models":["m"]}]}`,
	} {
		if mapping, err := parseEndpointMapping([]byte(body), true); err == nil || mapping != nil {
			t.Fatal("invalid discovery published a mapping")
		}
	}
	for _, host := range []string{"a.example.com", "127.0.0.1", "[::1]", "xn--a.near.ai", "-a.near.ai", "a_.near.ai", "a.near.ai:65536", "a.near.ai/path"} {
		body := fmt.Sprintf(`{"endpoints":[{"domain":%q,"models":["m"]}]}`, host)
		if _, err := parseEndpointMapping([]byte(body), true); err == nil {
			t.Errorf("accepted %q", host)
		}
	}
}

func TestDiscoveryMappingAndModelBounds(t *testing.T) {
	for _, count := range []int{maxDiscoveryMappings, maxDiscoveryMappings + 1} {
		models := make([]string, count)
		for i := range models {
			models[i] = fmt.Sprintf("model-%d", i)
		}
		body, err := json.Marshal(endpointsResponse{Endpoints: []endpointEntry{{Domain: "a.near.ai", Models: models}}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = parseEndpointMapping(body, true)
		if (err != nil) != (count > maxDiscoveryMappings) {
			t.Fatalf("mapping count %d: %v", count, err)
		}
	}
	for _, length := range []int{maxDiscoveryModelLength, maxDiscoveryModelLength + 1} {
		body := fmt.Sprintf(`{"endpoints":[{"domain":"a.near.ai","models":[%q]}]}`, strings.Repeat("a", length))
		_, err := parseEndpointMapping([]byte(body), true)
		if (err != nil) != (length > maxDiscoveryModelLength) {
			t.Fatalf("model length %d: %v", length, err)
		}
	}
}

func TestDiscoveryDecodedBodyBound(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, compressed := range []bool{false, true} {
			for _, extra := range []int{0, 1} {
				body := []byte(`{"endpoints":[{"domain":"a.near.ai","models":["m"]}]}`)
				body = append(body, bytes.Repeat([]byte(" "), maxDiscoveryBody+extra-len(body))...)
				ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if compressed {
						w.Header().Set("Content-Encoding", "gzip")
						writer := gzip.NewWriter(w)
						_, _ = writer.Write(body)
						_ = writer.Close()
						return
					}
					_, _ = w.Write(body)
				}))
				r := NewEndpointResolver()
				r.endpointsURL = ts.URL
				r.client = config.NewAttestationClient(false)
				_, err := r.Resolve(context.Background(), "m")
				r.client.CloseIdleConnections()
				if (err != nil) != (extra != 0) {
					t.Fatalf("compressed=%v extra=%d: %v", compressed, extra, err)
				}
			}
		}
	})
}
