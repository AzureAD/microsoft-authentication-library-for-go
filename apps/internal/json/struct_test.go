// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package json

import (
	"bytes"
	"encoding/json"
	"reflect"
	"runtime"
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

func TestDecoderStart(t *testing.T) {
	tests := []struct {
		desc    string
		b       []byte
		i       interface{}
		stateFn stateFn
		err     bool
	}{
		{
			desc:    "No content to decode",
			i:       &StructA{},
			stateFn: nil,
			err:     true,
		},
		{
			desc:    "No opening brace",
			b:       []byte("3"),
			i:       &StructA{},
			stateFn: nil,
			err:     true,
		},
		{
			desc:    "Success",
			b:       []byte(`{"Name": "value"}`),
			i:       &StructA{},
			stateFn: (new(decoder).next),
		},
	}

	for _, test := range tests {
		dec := newDecoder(json.NewDecoder(bytes.NewBuffer(test.b)), reflect.ValueOf(test.i))
		stateFn, err := dec.start()
		switch {
		case err == nil && test.err:
			t.Errorf("TestDecoderStart(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestDecoderStart(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		gotStateFn := runtime.FuncForPC(reflect.ValueOf(stateFn).Pointer()).Name()
		wantStateFn := runtime.FuncForPC(reflect.ValueOf(test.stateFn).Pointer()).Name()
		if gotStateFn != wantStateFn {
			t.Errorf("TestDecoderStart(%s): got(stateFn) %s, want %s", test.desc, gotStateFn, wantStateFn)
		}
	}
}

func TestDecoderNext(t *testing.T) {
	tests := []struct {
		desc string
		b    []byte
		// advToken advanced the decoder this may Token() calls, as the decoder only works
		// on well formed JSON.
		advToken int
		i        interface{}
		key      string
		stateFn  stateFn
		err      bool
	}{
		{
			desc:    "No content to decode",
			i:       &StructA{},
			stateFn: nil,
			err:     true,
		},
		{
			desc:     "Bad ] found",
			b:        []byte("{]"),
			advToken: 1,
			i:        &StructA{},
			stateFn:  nil,
			err:      true,
		},
		{
			desc:     "Closing brace",
			b:        []byte("{}"),
			advToken: 1,
			i:        &StructA{},
			stateFn:  nil,
			err:      false,
		},
		{
			desc:     "Success",
			b:        []byte(`{"Name": "value"}`),
			advToken: 1,
			i:        &StructA{},
			key:      "Name",
			stateFn:  (new(decoder).storeValue),
		},
	}

	for _, test := range tests {
		dec := newDecoder(json.NewDecoder(bytes.NewBuffer(test.b)), reflect.ValueOf(test.i))
		for i := 0; i < test.advToken; i++ {
			if _, err := dec.dec.Token(); err != nil {
				panic(err)
			}
		}

		stateFn, err := dec.next()
		switch {
		case err == nil && test.err:
			t.Errorf("TestDecoderNext(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestDecoderNext(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if dec.key != test.key {
			t.Errorf("TestDecoderNext(%s): got(.key) %s, want %s", test.desc, dec.key, test.key)
		}

		gotStateFn := runtime.FuncForPC(reflect.ValueOf(stateFn).Pointer()).Name()
		wantStateFn := runtime.FuncForPC(reflect.ValueOf(test.stateFn).Pointer()).Name()
		if gotStateFn != wantStateFn {
			t.Errorf("TestDecoderNext(%s): got(stateFn) %s, want %s", test.desc, gotStateFn, wantStateFn)
		}
	}
}

func TestDecoderStoreValue(t *testing.T) {
	tests := []struct {
		desc    string
		b       []byte
		want    StructA
		stateFn stateFn
	}{
		{
			desc:    "Field found, no struct tag",
			b:       []byte(`{"Name": "myName"}`),
			want:    StructA{Name: "myName"},
			stateFn: (new(decoder).next),
		},
		{
			desc:    "Field found, using struct tag",
			b:       []byte(`{"id": 3}`),
			want:    StructA{ID: 3},
			stateFn: (new(decoder).next),
		},
		{
			desc:    "Field not found, go to storeAdditional()",
			b:       []byte(`{"blah": 3}`),
			want:    StructA{},
			stateFn: (new(decoder).storeAdditional),
		},
	}

	for _, test := range tests {
		got := StructA{}
		dec := newDecoder(json.NewDecoder(bytes.NewBuffer(test.b)), reflect.ValueOf(&got).Elem())
		_, err := dec.start() // populates our translator field
		if err != nil {
			panic(err)
		}
		_, err = dec.next()
		if err != nil {
			panic(err)
		}

		stateFn, err := dec.storeValue()
		if err != nil {
			t.Errorf("TestDecoderStoreValue(%s): got err == %s, want err == nil", test.desc, err)
			continue
		}

		if diff := pretty.Compare(test.want, got); diff != "" {
			t.Errorf("TestDecoderStoreValue(%s): -want/+got:\n%s", test.desc, diff)
			continue
		}

		gotStateFn := runtime.FuncForPC(reflect.ValueOf(stateFn).Pointer()).Name()
		wantStateFn := runtime.FuncForPC(reflect.ValueOf(test.stateFn).Pointer()).Name()
		if gotStateFn != wantStateFn {
			t.Errorf("TestDecoderStoreValue(%s): got(stateFn) %s, want %s", test.desc, gotStateFn, wantStateFn)
		}
	}
}

func TestDecoderStoreAdditional(t *testing.T) {
	tests := []struct {
		desc    string
		b       []byte
		got     StructA
		want    StructA
		stateFn stateFn
	}{
		{
			desc: "Map not initialized",
			b:    []byte(`{"blah": "whatever"}`),
			got:  StructA{},
			want: StructA{
				AdditionalFields: map[string]interface{}{
					"blah": json.RawMessage(`"whatever"`),
				},
			},
			stateFn: (new(decoder).next),
		},
		{
			desc: "Map exists",
			b:    []byte(`{"blah": "whatever"}`),
			got: StructA{
				AdditionalFields: map[string]interface{}{
					"else": json.RawMessage(`"if"`),
				},
			},
			want: StructA{
				AdditionalFields: map[string]interface{}{
					"else": json.RawMessage(`"if"`),
					"blah": json.RawMessage(`"whatever"`),
				},
			},
			stateFn: (new(decoder).next),
		},
	}

	for _, test := range tests {
		dec := newDecoder(json.NewDecoder(bytes.NewBuffer(test.b)), reflect.ValueOf(&test.got).Elem())
		_, err := dec.start() // populates our translator field
		if err != nil {
			panic(err)
		}
		_, err = dec.next()
		if err != nil {
			panic(err)
		}

		stateFn, err := dec.storeAdditional()
		if err != nil {
			t.Errorf("TestDecoderStoreAdditional(%s): got err == %s, want err == nil", test.desc, err)
			continue
		}

		if diff := pretty.Compare(test.want, test.got); diff != "" {
			t.Errorf("TestDecoderStoreAdditional(%s): -want/+got:\n%s", test.desc, diff)
			continue
		}

		gotStateFn := runtime.FuncForPC(reflect.ValueOf(stateFn).Pointer()).Name()
		wantStateFn := runtime.FuncForPC(reflect.ValueOf(test.stateFn).Pointer()).Name()
		if gotStateFn != wantStateFn {
			t.Errorf("TestDecoderStoreAdditional(%s): got(stateFn) %s, want %s", test.desc, gotStateFn, wantStateFn)
		}
	}
}
