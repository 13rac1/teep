package verify

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
)

type nearCompletionReadFailure struct{}

func (nearCompletionReadFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestStandaloneNearSSECompletion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, suffix         string
		readFailure, wantErr bool
	}{
		{name: "no_space", suffix: "data:[DONE]\n\n"},
		{name: "crlf", suffix: "data:[DONE]\n\n"},
		{name: "cr", suffix: "data:[DONE]\n\n"},
		{name: "bom", suffix: "data:[DONE]\n\n"},
		{name: "plaintext_no_space", suffix: "data:{\"choices\":[{\"delta\":{\"content\":\"private upstream detail\"}}]}\n\ndata:[DONE]\n\n", wantErr: true},
		{name: "compact_trailing_data", suffix: "data:[DONE]\n\ndata:{}\n\n", wantErr: true},
		{name: "missing_reason", suffix: "data: [DONE]\n\n"},
		{name: "comments", suffix: "data: [DONE]\n\n: done\n\n"},
		{name: "usage", suffix: "data: {\"choices\":[],\"usage\":{}}\n\ndata: [DONE]\n\n"},
		{name: "missing_done", wantErr: true},
		{name: "provider_error", suffix: "data: {\"error\":{\"message\":\"private upstream detail\"}}\n\ndata: [DONE]\n\n", wantErr: true},
		{name: "null_error", suffix: "data: {\"error\":null}\n\ndata: [DONE]\n\n", wantErr: true},
		{name: "named_error", suffix: "event: error\ndata: {}\n\ndata: [DONE]\n\n", wantErr: true},
		{name: "trailing_data", suffix: "data: [DONE]\n\ndata: {}\n\n", wantErr: true},
		{name: "late_read_failure", suffix: "data: [DONE]\n\n", readFailure: true, wantErr: true},
		{name: "excess_tail", suffix: "data: [DONE]\n\n" + strings.Repeat(":\n", 64<<10), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			session, err := e2ee.NewNearCloudSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Zero()
			public, err := hex.DecodeString(session.ClientEd25519PubHex())
			if err != nil {
				t.Fatal(err)
			}
			recipient, err := e2ee.Ed25519PubToX25519(public)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := e2ee.EncryptXChaCha20([]byte("answer"), recipient)
			if err != nil {
				t.Fatal(err)
			}
			prefix := fmt.Sprintf("data: {\"id\":\"test\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", encrypted)
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
				body = io.MultiReader(body, nearCompletionReadFailure{})
			}
			result := verifyE2EEStreamResponse(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body)}, session, "nearcloud")
			if (result.Err != nil) != tc.wantErr {
				t.Fatalf("completion error: %v", result.Err)
			}
			if tc.readFailure && !errors.Is(result.Err, io.ErrUnexpectedEOF) {
				t.Fatalf("read error lost: %v", result.Err)
			}
			if result.Err != nil && strings.Contains(result.Err.Error(), "private upstream detail") {
				t.Fatal("provider error payload exposed")
			}
		})
	}
}
