// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package json

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
)

type StructA struct {
	Name             string
	ID               int `json:"id"`
	Meta             *StructB
	AdditionalFields map[string]interface{}
}

type StructB struct {
	Address          string
	AdditionalFields map[string]interface{}
}

type StructC struct {
	Time             time.Time
	Project          StructD
	AdditionalFields map[string]interface{}
}

type StructD struct {
	Project          string
	Info             StructE
	AdditionalFields map[string]interface{}
}

type StructE struct {
	Employees        int
	AdditionalFields map[string]interface{}
}

func TestUnmarshalRoundTrip(t *testing.T) {
	now := time.Now()
	nowJSON, err := now.MarshalJSON()
	if err != nil {
		panic(err)
	}

	tests := []struct {
		desc string
		b    []byte
		got  interface{}
		want interface{}
		err  bool
	}{
		{
			desc: "receiver not a pointer",
			got:  StructA{},
			b:    []byte(`{"content": "value"}`),
			err:  true,
		},
		{
			desc: "receiver not a pointer to a struct",
			got:  new(string),
			b:    []byte(`{"content": "value"}`),
			err:  true,
		},
		{
			desc: "AdditionalFields not a map",
			b:    []byte(`{"content": "value"}`),
			got: &struct {
				AdditionalFields string
			}{},
			err: true,
		},
		{
			desc: "Success, no json.Unmarshaler types",
			b: []byte(
				`
				{
					"Name": "John",
					"id": 3,
					"Meta": {
						"Address": "291 Street",
						"unknown0": 3.2
					},
					"unknown0": 10,
					"unknown1": "hello"
				}
				`,
			),
			got: &StructA{},
			want: &StructA{
				Name: "John",
				ID:   3,
				Meta: &StructB{
					Address: "291 Street",
					AdditionalFields: map[string]interface{}{
						"unknown0": MarshalRaw(3.2),
					},
				},
				AdditionalFields: map[string]interface{}{
					"unknown0": MarshalRaw(10),
					"unknown1": MarshalRaw("hello"),
				},
			},
		},
		{
			desc: "Success, a type has json.Unmarshaler",
			b: []byte(fmt.Sprintf(`
				{
					"Time":%s,
					"Project": {
						"Project":"myProject",
						"Info":{
							"Employees":2
						}
					}
				}
			`, string(nowJSON))),
			got: &StructC{},
			want: &StructC{
				Time: now,
				Project: StructD{
					Project: "myProject",
					Info: StructE{
						Employees: 2,
					},
				},
			},
		},
	}

	for _, test := range tests {
		err := Unmarshal(test.b, test.got)
		switch {
		case err == nil && test.err:
			t.Errorf("TestUnmarshal(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestUnmarshal(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}
		if diff := (&pretty.Config{IncludeUnexported: false}).Compare(test.want, test.got); diff != "" {
			t.Errorf("TestUnmarshal(%s): -want/+got:\n%s", test.desc, diff)
			continue
		}
		b, err := Marshal(test.got)
		if err != nil {
			t.Errorf("TestUnmarshal(%s): Marshal failed: %s", test.desc, err)
			continue
		}
		err = Unmarshal(b, test.got)
		if err != nil {
			t.Errorf("TestUnmarshal(%s): Unmarshal round trip failed: %s", test.desc, err)
			continue
		}
		if diff := (&pretty.Config{IncludeUnexported: false}).Compare(test.want, test.got); diff != "" {
			t.Errorf("TestUnmarshal(%s): Round trip failed. -want/+got:\n%s", test.desc, diff)
			continue
		}
	}
}

func TestIsDelim(t *testing.T) {
	tests := []struct {
		desc  string
		token json.Token
		want  bool
	}{
		{desc: "Is delim", token: json.Delim('{'), want: true},
		{desc: "Not a delim", token: json.Token("{"), want: false},
	}

	for _, test := range tests {
		got := isDelim(test.token)
		if got != test.want {
			t.Errorf("TestIsDelim(%s): got %v, want %v", test.desc, got, test.want)
		}
	}
}

func TestDelimIs(t *testing.T) {
	tests := []struct {
		desc  string
		token json.Token
		delim rune
		want  bool
	}{
		{desc: "Token is a match", token: json.Delim('{'), delim: '{', want: true},
		{desc: "Token is not a match", token: json.Delim('{'), delim: '}', want: false},
	}

	for _, test := range tests {
		got := delimIs(test.token, test.delim)
		if got != test.want {
			t.Errorf("TestDelimIs(%s): got %v, want %v", test.desc, got, test.want)
		}
	}
}

// panicUnmarshaler is a type whose UnmarshalJSON always panics. It is used to
// simulate a panic escaping the reflect-based decoder so we can verify that
// Unmarshal recovers and returns an error instead of crashing the caller.
type panicUnmarshaler struct{}

func (p *panicUnmarshaler) UnmarshalJSON(_ []byte) error {
	panic("reflect: New of type that may not be allocated in heap (possibly undefined cgo C type)")
}

type withPanicField struct {
	Inner            map[string]panicUnmarshaler
	AdditionalFields map[string]interface{}
}

// TestUnmarshalPanicRecovery verifies that a panic originating deep in the
// reflect-based decoder (see issue #579) is converted into an error by
// Unmarshal rather than propagating to the caller. The panic unwinds through
// the same frames as the #579 stack trace
// (unmarshalStruct -> decoder.storeValue -> unmarshalMap -> mapWalk.run ->
// mapWalk.storeStruct -> unmarshalStruct), so this proves the recover()
// boundary catches panics on the reported code path.
func TestUnmarshalPanicRecovery(t *testing.T) {
	target := &withPanicField{}
	err := Unmarshal([]byte(`{"Inner":{"k":{}}}`), target)
	if err == nil {
		t.Fatal("TestUnmarshalPanicRecovery: expected an error from recovered panic, got nil")
	}
	if !strings.Contains(err.Error(), "panic during Unmarshal") {
		t.Errorf("TestUnmarshalPanicRecovery: expected error to mention recovered panic, got %q", err.Error())
	}
}

// runtimePanicUnmarshaler triggers a real runtime.Error (nil pointer
// dereference) from inside its UnmarshalJSON. The original #579 panic
// ("reflect: New of type that may not be allocated in heap") is also a
// runtime.Error emitted by reflect.New, but a notinheap type cannot be
// constructed from user code. Triggering a nil-deref runtime.Error here is
// the closest faithful reproduction available and proves that Unmarshal's
// recover() catches runtime-level panics (not just panics with string args).
type runtimePanicUnmarshaler struct{}

func (r *runtimePanicUnmarshaler) UnmarshalJSON(_ []byte) error {
	var p *int
	_ = *p // nil pointer dereference -> runtime.Error panic
	return nil
}

type runtimePanicMapHolder struct {
	Inner            map[string]runtimePanicUnmarshaler
	AdditionalFields map[string]interface{}
}

type runtimePanicSliceHolder struct {
	Inner            []runtimePanicUnmarshaler
	AdditionalFields map[string]interface{}
}

type runtimePanicStructHolder struct {
	Inner            runtimePanicUnmarshaler
	AdditionalFields map[string]interface{}
}

// TestUnmarshalRuntimePanicRecovery is a regression test that locks in
// recover() coverage for every reflect-bearing code path inside the json
// package. If a future change moves the recover, restructures the unwind, or
// otherwise lets a runtime panic escape Unmarshal on any of these paths, this
// test will fail.
//
// Paths covered:
//   - map[string]<struct>  -> mapslice.mapWalk.storeStruct (exact #579 frames)
//   - []<struct>           -> mapslice.sliceWalk.storeStruct
//   - <struct> field       -> struct.go decoder.storeValue (struct branch)
func TestUnmarshalRuntimePanicRecovery(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		target interface{}
	}{
		{
			name:   "map of struct (issue #579 stack)",
			input:  `{"Inner":{"k":{}}}`,
			target: &runtimePanicMapHolder{},
		},
		{
			name:   "slice of struct",
			input:  `{"Inner":[{}]}`,
			target: &runtimePanicSliceHolder{},
		},
		{
			name:   "nested struct field",
			input:  `{"Inner":{}}`,
			target: &runtimePanicStructHolder{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Unmarshal([]byte(test.input), test.target)
			if err == nil {
				t.Fatalf("expected an error from recovered runtime panic on path %q, got nil", test.name)
			}
			if !strings.Contains(err.Error(), "panic during Unmarshal") {
				t.Errorf("expected error to mention recovered panic on path %q, got %q", test.name, err.Error())
			}
		})
	}
}
