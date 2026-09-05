package provider

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestKeyRejection(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		media, body string
		want        bool
		bad         bool
	}{
		{"tinfoil_v3_cloud", 422, "application/problem+json", `{"type":"urn:ietf:params:ehbp:error:key-config"}`, true, false},
		{"tinfoil_v3_direct", 422, "application/problem+json", `{"type":"other","title":"key-config"}`, false, false},
		{"tinfoil_v3_cloud", 422, "application/json", `{"type":"urn:ietf:params:ehbp:error:key-config"}`, false, false},
		{"tinfoil_v3_cloud", 422, "application/problem+json", `{"title":"key-config"}`, false, true},
		{"tinfoil_v3_cloud", 422, "application/problem+json", strings.Repeat("x", (64<<10)+1), false, true},
		{"tinfoil_v3_cloud", 503, "application/problem+json", `{"type":"urn:ietf:params:ehbp:error:key-config"}`, false, false},
		{"neardirect", 400, "application/json", `{"error":{"type":"bad_request","message":"Decryption failed"}}`, true, false},
		{"nearcloud", 400, "application/json", `{"error":{"type":"invalid_request_error","message":"Decryption failed"}}`, true, false},
		{"nearcloud", 400, "application/json", `{"error":{"type":"invalid_request_error","message":"Decryption failed!"}}`, false, false},
	} {
		t.Run(tc.name+tc.body[:min(len(tc.body), 35)], func(t *testing.T) {
			resp := &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {tc.media}}, Body: io.NopCloser(strings.NewReader(tc.body))}
			got, err := KeyRejection(resp, tc.name, "/v1/chat/completions")
			defer resp.Body.Close()
			if got != tc.want || (err != nil) != tc.bad {
				t.Fatalf("rejection=%v err=%v", got, err)
			}
			if !tc.bad {
				body, err := io.ReadAll(resp.Body)
				if err != nil || string(body) != tc.body {
					t.Fatal("response body was consumed")
				}
			}
		})
	}
}
