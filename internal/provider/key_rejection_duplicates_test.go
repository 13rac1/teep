package provider

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestKeyRejectionRejectsDuplicateMembers(t *testing.T) {
	for _, name := range []string{"neardirect", "nearcloud", "tinfoil_v3_cloud", "tinfoil_v3_direct"} {
		t.Run(name, func(t *testing.T) {
			status, media := http.StatusUnprocessableEntity, "application/problem+json"
			bodies := []string{
				`{"type":"other","type":"urn:ietf:params:ehbp:error:key-config"}`,
				`{"type":"urn:ietf:params:ehbp:error:key-config","type":"other"}`,
				`{"type":"urn:ietf:params:ehbp:error:key-config","type":"urn:ietf:params:ehbp:error:key-config"}`,
				`{"type":"other","\u0074ype":"urn:ietf:params:ehbp:error:key-config"}`,
			}
			if name == "neardirect" || name == "nearcloud" {
				rejectionType := "bad_request"
				if name == "nearcloud" {
					rejectionType = "invalid_request_error"
				}
				status, media = http.StatusBadRequest, "application/json"
				detail := `{"type":"` + rejectionType + `","message":"Decryption failed"}`
				bodies = []string{
					`{"error":{"type":"other","message":"inference failed"},"error":` + detail + `}`,
					`{"error":{"type":"other","type":"` + rejectionType + `","message":"Decryption failed"}}`,
					`{"error":{"type":"` + rejectionType + `","message":"inference failed","message":"Decryption failed"}}`,
					`{"error":{"type":"` + rejectionType + `","message":"Decryption failed","message":"Decryption failed"}}`,
					`{"error":{"type":"` + rejectionType + `","message":"inference failed","\u006dessage":"Decryption failed"}}`,
					`{"error":{"type":"` + rejectionType + `","message":"Decryption failed","param":[{"a":1,"a":2}]}}`,
				}
			}
			for _, body := range bodies {
				resp := &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {media}}, Body: io.NopCloser(strings.NewReader(body))}
				retry, err := KeyRejection(resp, name, "/v1/chat/completions")
				retained, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if retry || err == nil {
					t.Errorf("ambiguous envelope authorized retry: %s", body)
				}
				if readErr != nil || string(retained) != body {
					t.Fatal("rejected envelope body was not restored")
				}
			}
		})
	}
}
