package nearparse

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// Event retains one validated event and its schema diagnostics.
type Event struct {
	Value   attestation.EventLogEntry
	unknown []string
}

// UnmarshalJSON validates every supported field before assignment.
func (e *Event) UnmarshalJSON(data []byte) error {
	var entry attestation.EventLogEntry
	unknown, err := Object(data, &entry, "event")
	if err != nil {
		return err
	}
	*e = Event{Value: entry, unknown: unknown}
	return nil
}

// EventLog is a bounded array of strictly decoded events.
type EventLog []Event

// UnmarshalJSON requires a non-null array and validates every entry.
func (e *EventLog) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '[' || len(data) > MaxEvidenceBytes {
		return errors.New("event_log: expected bounded array")
	}
	var wrapped struct {
		Value []json.RawMessage `json:"value"`
	}
	if _, _, err := jsonstrict.Unmarshal(append(append([]byte(`{"value":`), data...), '}'), &wrapped); err != nil {
		return fmt.Errorf("event_log: %w", err)
	}
	if len(wrapped.Value) > MaxEvents {
		return errors.New("event_log: too many events")
	}
	out := make(EventLog, len(wrapped.Value))
	for i, raw := range wrapped.Value {
		if err := out[i].UnmarshalJSON(raw); err != nil {
			return fmt.Errorf("event_log[%d]: %w", i, err)
		}
	}
	*e = out
	return nil
}

// Values returns verification inputs without unknown additions.
func (e EventLog) Values() []attestation.EventLogEntry {
	out := make([]attestation.EventLogEntry, len(e))
	for i, entry := range e {
		out[i] = entry.Value
	}
	return out
}

// UnknownFields returns paths for each entry without logging or deduplication.
func (e EventLog) UnknownFields(path string) []string {
	var out []string
	for i, entry := range e {
		for _, field := range entry.unknown {
			out = append(out, fmt.Sprintf("%s[%d].%s", path, i, strings.TrimPrefix(field, "event.")))
		}
	}
	return out
}

// EncodedEventLog accepts the gateway's single JSON-string encoding.
type EncodedEventLog struct{ Log EventLog }

// UnmarshalJSON validates the decoded document, including duplicate members.
func (e *EncodedEventLog) UnmarshalJSON(data []byte) error {
	var wrapped struct {
		Value string `json:"value"`
	}
	if _, _, err := jsonstrict.Unmarshal(append(append([]byte(`{"value":`), data...), '}'), &wrapped); err != nil {
		return err
	}
	var entries EventLog
	if err := entries.UnmarshalJSON([]byte(wrapped.Value)); err != nil {
		return err
	}
	*e = EncodedEventLog{Log: entries}
	return nil
}
