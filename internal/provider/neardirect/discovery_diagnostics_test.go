package neardirect

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestEndpointDiscoveryReturnsDiagnosticsWithoutLogging(t *testing.T) {
	const childEnv = "TEEP_DISCOVERY_DIAGNOSTICS_CHILD"
	if os.Getenv(childEnv) != "1" {
		// Observe the default logger in an isolated process without changing shared state.
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestEndpointDiscoveryReturnsDiagnosticsWithoutLogging$")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("parser subprocess failed: %v\n%s\n%s", err, output, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("parser logged diagnostics: %s", stderr.String())
		}
		return
	}
	for _, tc := range []struct {
		body string
		want string
	}{
		{`{"endpoints":[{"domain":"a.near.ai","models":["known"]}],"unexpected_field":true}`, "unknown [unexpected_field]"},
		{`{}`, "missing [endpoints]"},
	} {
		mapping, err := parseEndpointMapping([]byte(tc.body), true)
		if mapping != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("mapping=%v error=%v, want rejection containing %q", mapping, err, tc.want)
		}
	}
}
