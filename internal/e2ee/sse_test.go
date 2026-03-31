package e2ee

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSSEScanner(t *testing.T) {
	input := "data: {\"chunk\":1}\n\ndata: {\"chunk\":2}\n\ndata: [DONE]\n\n"
	scanner, cleanup := newSSEScanner(strings.NewReader(input))
	defer cleanup()

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	t.Logf("scanned %d lines", len(lines))
	for i, line := range lines {
		t.Logf("  line[%d]: %q", i, line)
	}

	// SSE format: data lines separated by blank lines.
	want := []string{
		`data: {"chunk":1}`,
		``,
		`data: {"chunk":2}`,
		``,
		`data: [DONE]`,
		``,
	}
	if len(lines) != len(want) {
		t.Fatalf("line count = %d, want %d", len(lines), len(want))
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line[%d] = %q, want %q", i, lines[i], w)
		}
	}
}

func TestNewSSEScanner_PoolReuse(t *testing.T) {
	// Create and release a scanner, then create another to verify pool reuse.
	s1, c1 := newSSEScanner(strings.NewReader("line1\n"))
	_ = s1.Scan()
	c1()

	s2, c2 := newSSEScanner(strings.NewReader("line2\n"))
	defer c2()
	if !s2.Scan() {
		t.Fatal("second scanner failed to scan")
	}
	if s2.Text() != "line2" {
		t.Errorf("second scanner: got %q, want %q", s2.Text(), "line2")
	}
	t.Logf("pool reuse successful")
}

func TestWriteSSEError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteSSEError(rec, rec, "test error message")

	body := rec.Body.String()
	t.Logf("SSE error body: %q", body)

	if !strings.Contains(body, "event: error\n") {
		t.Error("missing 'event: error' line")
	}
	if !strings.Contains(body, `"message":"test error message"`) {
		t.Error("missing error message in body")
	}
	if !strings.Contains(body, `"type":"decryption_error"`) {
		t.Error("missing decryption_error type")
	}
}

func TestSafePrefix(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"shorter_than_n", "abc", 10, "abc"},
		{"equal_to_n", "abcde", 5, "abcde"},
		{"longer_than_n", "abcdefghij", 5, "abcde"},
		{"empty_string", "", 5, ""},
		{"n_is_zero", "abc", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SafePrefix(tt.s, tt.n)
			if got != tt.want {
				t.Errorf("SafePrefix(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
			}
			t.Logf("SafePrefix(%q, %d) = %q", tt.s, tt.n, got)
		})
	}
}
