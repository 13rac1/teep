package e2ee

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNearSSECompletion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, finish, suffix string
		readFailure, wantErr bool
	}{
		{name: "no_space", suffix: "data:[DONE]\n\n"},
		{name: "crlf", suffix: "data:[DONE]\n\n"},
		{name: "cr", suffix: "data:[DONE]\n\n"},
		{name: "bom", suffix: "data:[DONE]\n\n"},
		{name: "plaintext_no_space", suffix: "data:{\"choices\":[{\"delta\":{\"content\":\"private upstream detail\"}}]}\n\ndata:[DONE]\n\n", wantErr: true},
		{name: "compact_trailing_data", suffix: "data:[DONE]\n\ndata:{}\n\n", wantErr: true},
		{name: "missing_reason", suffix: "data: [DONE]\n\n"},
		{name: "stop", finish: "stop", suffix: "data: [DONE]\n\n"},
		{name: "length", finish: "length", suffix: "data: [DONE]\n\n"},
		{name: "tool_calls", finish: "tool_calls", suffix: "data: [DONE]\n\n"},
		{name: "comments", suffix: "data: [DONE]\n\n: done\n\n"},
		{name: "usage", suffix: "data: {\"choices\":[],\"usage\":{\"completion_tokens\":1}}\n\ndata: [DONE]\n\n"},
		{name: "missing_done", wantErr: true},
		{name: "finish_without_done", finish: "stop", wantErr: true},
		{name: "provider_error", suffix: "data: {\"error\":{\"message\":\"private upstream detail\"}}\n\ndata: [DONE]\n\n", wantErr: true},
		{name: "null_error", suffix: "data: {\"error\":null}\n\ndata: [DONE]\n\n", wantErr: true},
		{name: "named_error", suffix: "event: error\ndata: {}\n\ndata: [DONE]\n\n", wantErr: true},
		{name: "trailing_data", suffix: "data: [DONE]\n\ndata: {}\n\n", wantErr: true},
		{name: "trailing_error", suffix: "data: [DONE]\n\n", readFailure: true, wantErr: true},
		{name: "excess_tail", suffix: "data: [DONE]\n\n" + strings.Repeat(":\n", 64<<10), wantErr: true},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream_%v", tc.name, stream), func(t *testing.T) {
				t.Parallel()
				session, err := NewNearCloudSession()
				if err != nil {
					t.Fatal(err)
				}
				defer session.Zero()
				public, err := hex.DecodeString(session.ClientEd25519PubHex())
				if err != nil {
					t.Fatal(err)
				}
				recipient, err := Ed25519PubToX25519(public)
				if err != nil {
					t.Fatal(err)
				}
				encrypted, err := EncryptXChaCha20([]byte("answer"), recipient)
				if err != nil {
					t.Fatal(err)
				}
				prefix := fmt.Sprintf("data: {\"id\":\"test\",\"model\":\"model\",\"created\":1,\"choices\":[{\"delta\":{\"content\":%q},\"finish_reason\":%q}]}\n\n", encrypted, tc.finish)
				wire := prefix + tc.suffix
				switch tc.name {
				case "no_space":
					wire = strings.ReplaceAll(wire, "data: ", "data:")
				case "crlf":
					wire = strings.ReplaceAll(wire, "\n", "\r\n")
				case "cr":
					wire = strings.ReplaceAll(wire, "\n", "\r")
				case "bom":
					wire = "\uFEFF" + wire
				}
				var body io.Reader = strings.NewReader(wire)
				if tc.readFailure {
					body = io.MultiReader(body, completionReadFailure{})
				}
				rec := httptest.NewRecorder()
				if stream {
					_, err = RelayStream(t.Context(), rec, body, session, EndpointChat)
				} else {
					_, err = RelayReassembledNonStream(t.Context(), rec, body, session, EndpointChat)
				}
				if (err != nil) != tc.wantErr {
					t.Fatalf("completion error: %v", err)
				}
				if errors.Is(err, ErrDecryptionFailed) && tc.name != "plaintext_no_space" {
					t.Fatal("protocol failure classified as authentication failure")
				}
				if tc.readFailure && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("read failure lost: %v", err)
				}
				if tc.wantErr {
					if strings.Contains(rec.Body.String(), "data: [DONE]") || (!stream && rec.Code != 502) {
						t.Fatal("invalid response reported success")
					}
					if strings.Contains(rec.Body.String(), "private upstream detail") || (err != nil && strings.Contains(err.Error(), "private upstream detail")) {
						t.Fatal("provider error payload exposed")
					}
				} else if !stream && tc.name != "usage" {
					reason := tc.finish
					if reason == "" {
						reason = "stop"
					}
					if !strings.Contains(rec.Body.String(), `"finish_reason":"`+reason+`"`) {
						t.Fatal("finish reason changed")
					}
				}
			})
		}
	}
}
