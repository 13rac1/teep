package proxy

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct"
)

func TestLiveInferenceFailureRedactsDetails(t *testing.T) {
	for _, tc := range []struct {
		err      error
		category string
	}{
		{&url.Error{Op: "Post", URL: "https://example.com/private", Err: errors.New("private response text")}, "transport"},
		{errors.New("private response text"), "response"},
		{context.Canceled, "canceled"},
		{context.DeadlineExceeded, "deadline"},
		{tlsct.ErrConnectionCapacity, "connection_capacity"},
		{tlsct.ErrSPKIMismatch, "tls_trust"},
		{e2ee.ErrDecryptionFailed, "response_authentication"},
	} {
		got := liveInferenceFailure("upstream_failed", 0, tc.err).Error()
		if strings.Contains(got, "private") || !strings.Contains(got, "category="+tc.category) || !strings.Contains(got, "status=0") {
			t.Fatal("unsafe or missing failure classification")
		}
	}
}
