package jsonstrict

import (
	"strings"
	"sync"
	"testing"
)

func TestUnmarshalObjectBoundaries(t *testing.T) {
	for _, tc := range []struct {
		body    string
		valid   bool
		unknown int
	}{
		{`{"name":"valid"}`, true, 0},
		{`{"name":"valid","NAME":"overwrite"}`, true, 1},
		{`{"name":"valid","extra":{"x":1}}`, true, 1},
		{`{"name":"valid","extra":{"x":1,"x":2}}`, false, 0},
		{`{"name":"valid","\u006eame":"duplicate"}`, false, 0},
		{`{"NAME":"missing"}`, false, 0},
		{`{"name":null}`, false, 0},
		{`{"name":2}`, false, 0},
		{`null`, false, 0},
		{`[]`, false, 0},
		{`{"name":"valid"} {}`, false, 0},
	} {
		t.Run(tc.body, func(t *testing.T) {
			var value struct {
				Name string `json:"name"`
			}
			unknown, err := UnmarshalObject([]byte(tc.body), &value, "object")
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected validity: %v", err)
			}
			if tc.valid && (value.Name != "valid" || len(unknown) != tc.unknown) {
				t.Fatal("supported value or diagnostics changed")
			}
		})
	}
}

func TestUnmarshalObjectConcurrentNullable(t *testing.T) {
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			var value struct {
				Name *string `json:"name"`
			}
			unknown, err := UnmarshalObject([]byte(`{"name":null,"extra":true}`), &value, "object", "name")
			if err != nil || value.Name != nil || len(unknown) != 1 || unknown[0] != "object.extra" {
				t.Errorf("nullable decode: %v %v", unknown, err)
			}
		})
	}
	wg.Wait()
}

func BenchmarkUnmarshalObject(b *testing.B) {
	for _, extra := range []string{"", `,"extra":true`} {
		b.Run(extra, func(b *testing.B) {
			data := []byte(`{"name":"` + strings.Repeat("x", 1024) + `"` + extra + `}`)
			b.ReportAllocs()
			for b.Loop() {
				var value struct {
					Name string `json:"name"`
				}
				if _, err := UnmarshalObject(data, &value, "object"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
