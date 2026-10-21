package proxy

import (
	"log/slog"
	"testing"
)

func diagnosticFields(t *testing.T, attrs []slog.Attr) map[string]any {
	t.Helper()
	fields := make(map[string]any, len(attrs))
	for _, attr := range attrs {
		fields[attr.Key] = attr.Value.Any()
	}
	return fields
}
