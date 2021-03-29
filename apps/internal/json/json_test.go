// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package json

import (
	"encoding/json"
	"fmt"
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

func TestUnmarshal(t *testing.T) {
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
