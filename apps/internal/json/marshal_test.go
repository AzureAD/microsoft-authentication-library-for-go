// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package json

import (
	"encoding/json"
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

func TestMarshalStruct(t *testing.T) {
	tests := []struct {
		desc  string
		value interface{}
		want  map[string]interface{}
		err   bool
	}{
		{
			desc: "struct with no additional fields",
			value: struct {
				Name string
				Int  int
			}{
				Name: "my name",
				Int:  5,
			},
			want: map[string]interface{}{
				"Name": "my name",
				"Int":  5,
			},
		},
		{
			desc: "*struct with AdditionalFields",
			value: &struct {
				Name             string
				Int              int
				AdditionalFields map[string]interface{} `json:"-"`
			}{
				Name: "John Doak",
				Int:  45,
				AdditionalFields: map[string]interface{}{
					"Hello": "World",
					"Float": 3.2,
				},
			},
			want: map[string]interface{}{
				"Name":  "John Doak",
				"Int":   45,
				"Float": 3.2,
				"Hello": "World",
			},
		},
		{
			desc: "AdditionalFields is not a map",
			value: struct {
				AdditionalFields string `json:"-"`
			}{
				AdditionalFields: "hello",
			},
			err: true,
		},
		{
			desc: "AdditionalFields is not a map[string]interface{}",
			value: struct {
				AdditionalFields map[string]string `json:"-"`
			}{
				AdditionalFields: map[string]string{
					"Hello": "World",
				},
			},
			err: true,
		},
		{
			desc: "Multiple Structs",
			value: &StructA{
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
			want: map[string]interface{}{
				"Name": "John",
				"id":   3,
				"Meta": map[string]interface{}{
					"Address":  "291 Street",
					"unknown0": 3.2,
				},
				"unknown0": 10,
				"unknown1": "hello",
			},
		},
		{
			desc: "Struct with map[string]interface{}",
			value: struct {
				Name             string
				Map              map[string]interface{}
				AdditionalFields map[string]interface{}
			}{
				Name: "John",
				Map: map[string]interface{}{
					"key": "value",
				},
			},
			want: map[string]interface{}{
				"Name": "John",
				"Map": map[string]interface{}{
					"key": "value",
				},
			},
		},
		{
			desc: "Struct with map[string]struct{}",
			value: struct {
				Name             string
				Map              map[string]StructB
				AdditionalFields map[string]interface{}
			}{
				Name: "John",
				Map: map[string]StructB{
					"key": {
						Address: "addr",
					},
				},
			},
			want: map[string]interface{}{
				"Name": "John",
				"Map": map[string]interface{}{
					"key": map[string]interface{}{
						"Address": "addr",
					},
				},
			},
		},
		{
			desc: "Struct with map[string][]<basic type>",
			value: struct {
				Name             string
				Map              map[string]interface{}
				AdditionalFields map[string]interface{}
			}{
				Name: "John",
				Map: map[string]interface{}{
					"key": []string{
						"apples",
					},
				},
			},
			want: map[string]interface{}{
				"Name": "John",
				"Map": map[string]interface{}{
					"key": []string{"apples"},
				},
			},
		},
		{
			desc: "Struct with map[string][]struct",
			value: struct {
				Name             string
				Map              map[string][]StructB
				AdditionalFields map[string]interface{}
			}{
				Name: "John",
				Map: map[string][]StructB{
					"key": {
						{Address: "addr"},
					},
				},
			},
			want: map[string]interface{}{
				"Name": "John",
				"Map": map[string]interface{}{
					"key": []interface{}{
						map[string]interface{}{
							"Address": "addr",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		b, err := Marshal(test.value)
		switch {
		case err == nil && test.err:
			t.Errorf("TestMarshal(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestMarshal(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		got := map[string]interface{}{}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Errorf("TestMarshal(%s): Marshal produced invalid JSON:\n%s\n%s", test.desc, err, string(b))
			continue
		}
		if diff := pretty.Compare(test.want, got); diff != "" {
			t.Errorf("TestMarshal(%s): -want/+got:\n%s", test.desc, diff)
		}
	}
}

func TestEmptyTypes(t *testing.T) {
	type structA struct {
		EmptyMap   map[string]bool
		EmptySlice []string
		Slice      []string
		EmptyInt   int
		Int        int

		AdditionalFields map[string]interface{}
	}

	val := structA{
		EmptyMap: map[string]bool{},
		Slice:    []string{"hello"},
		Int:      1,
	}

	b, err := Marshal(val)
	if err != nil {
		t.Fatalf("TestEmptyTypes: unexpected error on Marshal: %v", err)
	}

	got := structA{}

	if err := Unmarshal(b, &got); err != nil {
		t.Fatalf("TestEmptyTypes: unexpected error when Umarshalling: %v", err)
	}

	if diff := pretty.Compare(got, val); diff != "" {
		t.Fatalf("TestEmptyTypes: -want/+got:\n%s", diff)
	}
}
