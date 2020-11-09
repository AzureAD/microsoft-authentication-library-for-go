package json

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

type StructWithUnmarshal struct {
	Name string
}

type StructName struct {
	Name             string
	AdditionalFields map[string]interface{}
}

func (s *StructWithUnmarshal) UnmarshalJSON(b []byte) error {
	// Note this looks sill, but you can't use json.Unmarshal
	// in an UnmarshalJSON, it causes a recursion loop. This is
	// just a simple workaround.
	type unmarshal struct {
		Name string
	}

	u := unmarshal{}
	err := json.Unmarshal(b, &u)
	if err != nil {
		panic(err)
	}
	s.Name = u.Name
	return nil
}

func TestUnmarshalMap(t *testing.T) {
	tests := []struct {
		desc  string
		input string
		got   interface{}
		want  interface{}
		err   bool
	}{
		{
			desc: "error: struct has no AdditionalFields",
			input: `
				{
					"key": {
						"Name": "John"
					}
				}
				`,
			got: &map[string]struct{ Name string }{},
			err: true,
		},
		{
			desc: "success: basic map[string]interface{}",
			input: `
			{
				"key": {
					"Name": "John"
				}
			}
			`,
			got: &map[string]interface{}{},
			want: map[string]interface{}{
				"key": map[string]interface{}{
					"Name": "John",
				},
			},
		},
		{
			desc: "success: struct has UnmarshalJSON",
			input: `
					{
						"key": {
							"Name": "John"
						}
					}
					`,
			got: &map[string]*StructWithUnmarshal{},
			want: map[string]*StructWithUnmarshal{
				"key": {
					Name: "John",
				},
			},
		},
		{
			desc: "success: map[string]struct",
			input: `
					{
						"key": {
							"Name": "John",
							"extra": "extra"
						}
					}
					`,
			got: &map[string]StructName{},
			want: map[string]StructName{
				"key": {
					Name: "John",
					AdditionalFields: map[string]interface{}{
						"extra": MarshalRaw("extra"),
					},
				},
			},
		},
		{
			desc: "success: map[string]*struct",
			input: `
					{
						"key": {
							"Name": "John",
							"extra": "extra"
						}
					}
					`,
			got: &map[string]*StructName{},
			want: map[string]*StructName{
				"key": {
					Name: "John",
					AdditionalFields: map[string]interface{}{
						"extra": MarshalRaw("extra"),
					},
				},
			},
		},
		{
			desc: "success: map[string][]struct",
			input: `
					{
						"key": [
								{
									"Name": "John",
									"extra": "extra"
								}
						]
					}
				`,
			got: &map[string][]StructName{},
			want: map[string][]StructName{
				"key": {
					{
						Name: "John",
						AdditionalFields: map[string]interface{}{
							"extra": MarshalRaw("extra"),
						},
					},
				},
			},
		},
		{
			desc: "success: map[string][]*struct",
			input: `
					{
						"key": [
								{
									"Name": "John",
									"extra": "extra"
								}
						]
					}
				`,
			got: &map[string][]*StructName{},
			want: map[string][]*StructName{
				"key": {
					{
						Name: "John",
						AdditionalFields: map[string]interface{}{
							"extra": MarshalRaw("extra"),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		dec := json.NewDecoder(bytes.NewBuffer([]byte(test.input)))
		err := unmarshalMap(dec, reflect.ValueOf(test.got))
		switch {
		case err == nil && test.err:
			t.Errorf("TestUnmarshalMap(%s): err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestUnmarshalMap(%s): err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if diff := pretty.Compare(test.want, test.got); diff != "" {
			t.Errorf("TestUnmarshalMap(%s): -want/+got\n%s", test.desc, diff)
		}
	}
}

func TestUnmarshalSlice(t *testing.T) {
	tests := []struct {
		desc  string
		input string
		got   interface{}
		want  interface{}
		err   bool
	}{
		{
			desc: "error: struct has no AdditionalFields",
			input: `
			[
				{
					"Name": "John"
				}
			]
			`,
			got: new([]struct{ Name string }),
			err: true,
		},
		{
			desc: "success: basic slice",
			input: `
					[
						"John",
						"Steve"
					]
				`,
			got:  new([]string),
			want: []string{"John", "Steve"},
		},
		{
			desc: "success: struct has UnmarshalJSON",
			input: `
					[
						{
							"Name": "John"
						}
					]
				`,
			got: new([]*StructWithUnmarshal),
			want: []*StructWithUnmarshal{
				{
					Name: "John",
				},
			},
		},
		{
			desc: "success: []struct",
			input: `
				[
					{
						"Name": "John",
						"extra": "extra"
					}
				]
			`,
			got: new([]StructName),
			want: []StructName{
				{
					Name: "John",
					AdditionalFields: map[string]interface{}{
						"extra": MarshalRaw("extra"),
					},
				},
			},
		},
		{
			desc: "success: []*struct",
			input: `
				[
					{
						"Name": "John",
						"extra": "extra"
					}
				]
			`,
			got: new([]*StructName),
			want: []*StructName{
				{
					Name: "John",
					AdditionalFields: map[string]interface{}{
						"extra": MarshalRaw("extra"),
					},
				},
			},
		},
		{
			desc: "success: [][]struct",
			input: `
					[
						[
							{
								"Name": "John",
								"extra": "extra"
							}
						]
					]
				`,
			got: new([][]StructName),
			want: [][]StructName{
				{
					{
						Name: "John",
						AdditionalFields: map[string]interface{}{
							"extra": MarshalRaw("extra"),
						},
					},
				},
			},
		},
		{
			desc: "success: [][]*struct",
			input: `
				[
					[
						{
							"Name": "John",
							"extra": "extra"
						}
					]
				]
			`,
			got: new([][]*StructName),
			want: [][]*StructName{
				{
					{
						Name: "John",
						AdditionalFields: map[string]interface{}{
							"extra": MarshalRaw("extra"),
						},
					},
				},
			},
		},
		{
			desc: "success: []map[string]struct",
			input: `
				[
					{
						"key": {
							"Name": "John",
							"extra": "extra"
						}
					}
				]
			`,
			got: new([]map[string]StructName),
			want: []map[string]StructName{
				{
					"key": {
						Name: "John",
						AdditionalFields: map[string]interface{}{
							"extra": MarshalRaw("extra"),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		dec := json.NewDecoder(bytes.NewBuffer([]byte(test.input)))
		err := unmarshalSlice(dec, reflect.ValueOf(test.got))
		switch {
		case err == nil && test.err:
			t.Errorf("TestUnmarshalSlice(%s): err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestUnmarshalSlice(%s): err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if diff := pretty.Compare(test.want, test.got); diff != "" {
			t.Errorf("TestUnmarshalSlice(%s): -want/+got\n%s", test.desc, diff)
		}
	}
}
