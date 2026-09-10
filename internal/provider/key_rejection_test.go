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
		{"unknown", 200, "application/json", `{}`, false, true},
		{"unknown", 400, "application/json", `{}`, false, true},
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

func TestNearKeyRejectionEndpoints(t *testing.T) {
	for _, name := range []string{"neardirect", "nearcloud"} {
		for _, path := range []string{"/v1/chat/completions", "/v1/embeddings", "/v1/images/generations", "/v1/rerank", "/v1/score", "/v1/audio/transcriptions"} {
			expected, known := nearRejectionType(name, path)
			body := `{"error":{"type":"` + expected + `","message":"Decryption failed"}}`
			resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
			rejected, err := KeyRejection(resp, name, path)
			resp.Body.Close()
			if err != nil || rejected != known {
				t.Fatalf("%s %s: rejected=%v err=%v", name, path, rejected, err)
			}
		}
	}
}

func TestNearKeyRejectionRejectsMalformedDetail(t *testing.T) {
	for _, detail := range []string{
		`{"type":"bad_request","message":"Decryption failed","unexpected":true}`,
		`{"type":"bad_request"}`,
		`{"message":"Decryption failed"}`,
		`{"type":null,"message":"Decryption failed"}`,
		`{"type":42,"message":"Decryption failed"}`,
		`null`, `[]`, `"error"`, `{}`,
	} {
		t.Run(detail, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"error":` + detail + `}`))}
			retry, err := KeyRejection(resp, "neardirect", "/v1/chat/completions")
			defer resp.Body.Close()
			if retry || err == nil {
				t.Fatalf("malformed detail: retry=%v err=%v", retry, err)
			}
		})
	}
}

func TestNearCloudExactStaleKeyRejection(t *testing.T) {
	valid := `{"error":{"type":"provider_error","message":"` + nearStaleKeyMessage + `"}}`
	for _, tt := range []struct {
		name, path, body string
		status           int
		want             bool
	}{
		{"nearcloud", "/v1/chat/completions", valid, 421, true},
		{"nearcloud", "/v1/chat/completions", strings.TrimSuffix(valid, "}}") + `,"param":null,"code":null}}`, 421, true},
		{"neardirect", "/v1/chat/completions", valid, 421, false},
		{"nearcloud", "/v1/images/generations", valid, 421, false},
		{"nearcloud", "/v1/embeddings", valid, 421, false},
		{"nearcloud", "/v1/chat/completions", valid, 400, false},
		{"nearcloud", "/v1/chat/completions", strings.Replace(valid, "provider_error", "invalid_request_error", 1), 421, false},
		{"nearcloud", "/v1/chat/completions", strings.Replace(valid, "retry.", "retry!", 1), 421, false},
	} {
		resp := &http.Response{StatusCode: tt.status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(tt.body))}
		got, err := KeyRejection(resp, tt.name, tt.path)
		resp.Body.Close()
		if err != nil || got != tt.want {
			t.Fatalf("%s %s status %d: rejected=%v err=%v", tt.name, tt.path, tt.status, got, err)
		}
	}
	for _, field := range []string{"param", "code"} {
		for _, value := range []string{`"text"`, `0`, `false`, `[]`, `{}`} {
			body := strings.TrimSuffix(valid, "}}") + `,"` + field + `":` + value + `}}`
			resp := &http.Response{StatusCode: http.StatusMisdirectedRequest, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
			got, err := KeyRejection(resp, "nearcloud", "/v1/chat/completions")
			resp.Body.Close()
			if got || err == nil {
				t.Fatal("non-null optional stale-key field authorized recovery")
			}
		}
	}
	for _, body := range []string{
		strings.TrimSuffix(valid, "}}") + `,"unknown":true}}`,
		strings.TrimSuffix(valid, "}}") + `,"type":"provider_error"}}`,
		strings.TrimSuffix(valid, "}}") + `,"t\u0079pe":"provider_error"}}`,
		`{"error":{"type":"provider_error"}}`,
		strings.Repeat("x", (64<<10)+1),
	} {
		resp := &http.Response{StatusCode: http.StatusMisdirectedRequest, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
		got, err := KeyRejection(resp, "nearcloud", "/v1/chat/completions")
		resp.Body.Close()
		if got || err == nil {
			t.Fatal("malformed stale-key response authorized recovery")
		}
	}
}
