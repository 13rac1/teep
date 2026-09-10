package nearparse

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestEvidenceBounds(t *testing.T) {
	for _, size := range []int{MaxEvidenceBytes, MaxEvidenceBytes + 1} {
		body := []byte(`{"value":"` + strings.Repeat("x", size-len(`{"value":""}`)) + `"}`)
		var target struct {
			Value string `json:"value"`
		}
		_, err := Object(body, &target, "test")
		if (err != nil) != (size > MaxEvidenceBytes) {
			t.Fatalf("Object size %d: %v", size, err)
		}
		_, err = EncodedObject(body)
		if (err != nil) != (size > MaxEvidenceBytes) {
			t.Fatalf("EncodedObject size %d: %v", size, err)
		}
	}
	const event = `{"imr":0,"digest":"ab","event_type":1,"event":"x","event_payload":"cd"}`
	for _, count := range []int{MaxEvents, MaxEvents + 1} {
		body := []byte("[" + strings.TrimSuffix(strings.Repeat(event+",", count), ",") + "]")
		var log EventLog
		if err := log.UnmarshalJSON(body); (err != nil) != (count > MaxEvents) {
			t.Fatalf("event count %d: %v", count, err)
		}
	}
	for _, body := range []string{"null", "[null]", "[" + strings.Repeat(" ", MaxEvidenceBytes) + "]"} {
		var events EventLog
		var models Models
		if events.UnmarshalJSON([]byte(body)) == nil || models.UnmarshalJSON([]byte(body)) == nil {
			t.Fatal("accepted invalid or oversized array")
		}
	}
}

func TestEncodedObjectLayers(t *testing.T) {
	object := `{"app_compose":"compose"}`
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	double, err := json.Marshal(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{object, true}, {string(encoded), true}, {string(double), false},
		{"null", false}, {`"null"`, false}, {`"[]"`, false}, {`""`, false},
	} {
		got, err := EncodedObject([]byte(tc.body))
		if (err == nil) != tc.valid || (err == nil && string(got) != object) {
			t.Fatalf("encoded object %q: %v", tc.body, err)
		}
	}
}

func TestEventPaths(t *testing.T) {
	var log EventLog
	if err := log.UnmarshalJSON([]byte(`[{"imr":0,"digest":"ab","event_type":1,"event":"x","event_payload":"cd","extension":true}]`)); err != nil {
		t.Fatal(err)
	}
	if got := log.UnknownFields("outer.events"); !reflect.DeepEqual(got, []string{"outer.events[0].extension"}) {
		t.Fatal(got)
	}
}

func TestModelEquality(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"ab", "0xAB", true}, {"0xab", "AB", true}, {"", "", true},
		{"a", "a", false}, {"ab", "abcd", false}, {"zz", "zz", false}, {"0Xab", "ab", false},
	} {
		if equalHex(tc.a, tc.b) != tc.same {
			t.Fatalf("hex comparison %q, %q", tc.a, tc.b)
		}
	}
	if !equalText("same", "same") || equalText("same", "Same") || equalText("same", "same-longer") {
		t.Fatal("text comparison")
	}
	base := Model{Fields: ModelFields{ModelName: "model", SigningPublicKey: "ab", SigningAddress: "ab", RequestNonce: "cd", TLSCertFingerprint: "ef"}}
	if !base.Equal(&base) {
		t.Fatal("identical model differs")
	}
	for _, mutate := range []func(*Model){
		func(m *Model) { m.Fields.ModelName = "other" },
		func(m *Model) { m.Fields.IntelQuote = "other" },
		func(m *Model) { m.Fields.SigningPublicKey = "ac" },
		func(m *Model) { m.Fields.SigningAddress = "ac" },
		func(m *Model) { m.Fields.RequestNonce = "ce" },
		func(m *Model) { m.Fields.TLSCertFingerprint = "ed" },
		func(m *Model) { m.Fields.Info.Info.AppName = "other" },
		func(m *Model) { m.Fields.Info.Info.TCBInfo.RTMR0 = "ab" },
		func(m *Model) { m.Fields.EventLog = EventLog{{}} },
	} {
		other := base
		mutate(&other)
		if base.Equal(&other) || other.Equal(&base) {
			t.Fatal("different model evidence compares equal")
		}
	}
	other := base
	other.unknown = []string{"model.extension"}
	other.Fields.SigningPublicKey = "0xAB"
	if !base.Equal(&other) {
		t.Fatal("encoding or unknown field changed supported evidence")
	}
}
