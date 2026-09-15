package tlsct

import "testing"

func TestInferenceProtocolBeforeAndAfterHeaders(t *testing.T) {
	for _, tc := range []struct{ name, alpn, response, phase string }{
		{"http2", "h2", "HTTP/2.0", "response_headers"},
		{"http1", "http/1.1", "HTTP/1.1", "request_write_or_response_headers"},
		{"unknown", "", "HTTP/1.1", "request_write_or_response_headers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt := &InferenceAttempt{}
			attempt.timing.gotConn(tc.alpn)
			if phase := diagnosticFields(attempt.TimingDiagnostics())["failure_phase"]; phase != "request_write" {
				t.Fatalf("phase before write = %v, want request_write", phase)
			}
			attempt.timing.wroteRequest(nil)
			before := diagnosticFields(attempt.TimingDiagnostics())
			if before["failure_phase"] != tc.phase || before["response_header_wait"] == nil {
				t.Fatalf("incorrect diagnostics after WroteRequest: %v", before)
			}
			if tc.alpn != "" && before["upstream_protocol"] != tc.response {
				t.Fatalf("protocol before headers = %v, want %s", before["upstream_protocol"], tc.response)
			}
			if tc.alpn == "" && before["upstream_protocol"] != nil {
				t.Fatalf("unknown protocol reported as %v", before["upstream_protocol"])
			}
			attempt.ResponseHeadersReceived(tc.response)
			after := diagnosticFields(attempt.TimingDiagnostics())
			if after["upstream_protocol"] != tc.response || after["failure_phase"] != "response_body" {
				t.Fatalf("incorrect diagnostics after headers: %v", after)
			}
		})
	}
}
