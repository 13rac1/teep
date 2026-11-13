package aci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

var (
	rawMessageType = reflect.TypeFor[json.RawMessage]()
	numberType     = reflect.TypeFor[json.Number]()
)

// checkShape requires that data has exactly the members of t at every depth:
// each JSON object that maps to a struct carries every field of the struct
// and no other member. A pointer field may be null; every other field must
// be present. jsonstrict reports unknown and missing fields only for the top
// level, so a member nested in the report would otherwise pass unseen.
// path names data in errors.
func checkShape(data json.RawMessage, t reflect.Type, path string) error {
	data = bytes.TrimSpace(data)
	if t.Kind() == reflect.Pointer {
		if string(data) == "null" {
			return nil
		}
		t = t.Elem()
	}
	switch {
	case t == rawMessageType || t == numberType:
		return nil
	case t.Kind() == reflect.Struct:
		return checkStructShape(data, t, path)
	case t.Kind() == reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return fmt.Errorf("%s: expected a list", path)
		}
		for i, item := range items {
			if err := checkShape(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkStructShape(data json.RawMessage, t reflect.Type, path string) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
		return fmt.Errorf("%s: expected an object", path)
	}
	fields := map[string]reflect.StructField{}
	for _, f := range reflect.VisibleFields(t) {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		fields[name] = f
	}
	var undefined []string
	for name := range members {
		if _, ok := fields[name]; !ok {
			undefined = append(undefined, path+"."+name)
		}
	}
	if len(undefined) > 0 {
		slices.Sort(undefined)
		return fmt.Errorf("undefined fields %q", undefined)
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		value, ok := members[name]
		if !ok {
			return fmt.Errorf("lacks fields [%q]", path+"."+name)
		}
		if err := checkShape(value, fields[name].Type, path+"."+name); err != nil {
			return err
		}
	}
	return nil
}
