// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	customJSON "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json"
	"github.com/kylelemons/godebug/diff"
	"github.com/kylelemons/godebug/pretty"
)

type recorder struct {
	xml bool

	statusCode int
	ret        interface{}

	gotMethod  string
	gotQV      url.Values
	gotBody    []byte
	gotHeaders http.Header
}

func (rec *recorder) reset() {
	rec.statusCode = 0
	rec.ret = nil
	rec.gotMethod = ""
	rec.gotQV = nil
	rec.gotBody = nil
	rec.gotHeaders = nil
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rec.statusCode != http.StatusOK {
		http.Error(w, "error", http.StatusBadRequest)
		return
	}
	rec.gotMethod = r.Method
	rec.gotQV = r.URL.Query()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	rec.gotBody = b

	// This gets added by the test server.
	delete(r.Header, "User-Agent")
	delete(r.Header, "Content-Length")

	rec.gotHeaders = r.Header

	if rec.xml {
		b, err = xml.Marshal(rec.ret)
		if err != nil {
			panic(err)
		}
	} else {
		b, err = customJSON.Marshal(rec.ret)
		if err != nil {
			panic(err)
		}
	}

	if _, err := w.Write(b); err != nil {
		panic(err)
	}
}

type SampleData struct {
	Ok string
}

func init() {
	testID = "testID"
}

func TestJSONCall(t *testing.T) {
	tests := []struct {
		desc       string
		statusCode int
		headers    http.Header
		qv         url.Values
		body, resp interface{}

		expectMethod  string
		expectHeaders http.Header
		expectBody    interface{}

		want interface{}
		err  bool
	}{
		{
			desc:       "Error: non-struct resp value",
			statusCode: http.StatusOK,
			resp:       new(int),
			err:        true,
		},
		{
			desc:       "Error: non-pointer resp value",
			statusCode: http.StatusOK,
			resp:       SampleData{},
			err:        true,
		},
		{
			desc:          "Body == nil[http Get]",
			statusCode:    http.StatusOK,
			headers:       http.Header{"header": []string{"here"}},
			qv:            url.Values{"key": []string{"value"}},
			resp:          &SampleData{Ok: "true"},
			expectMethod:  http.MethodGet,
			expectHeaders: addStdHeaders(http.Header{"Header": []string{"here"}}),
			want:          &SampleData{Ok: "true"},
		},
		{
			desc:         "Body != nil[http Post]",
			statusCode:   http.StatusOK,
			headers:      http.Header{"header": []string{"here"}},
			qv:           url.Values{"key": []string{"value"}},
			body:         &SampleData{Ok: "false"},
			resp:         &SampleData{Ok: "true"},
			expectMethod: http.MethodPost,
			expectHeaders: addStdHeaders(
				http.Header{
					"Header":       []string{"here"},
					"Content-Type": []string{"application/json; charset=utf-8"},
				},
			),
			want: &SampleData{Ok: "true"},
		},
		{
			desc:       "Error: non-200 response",
			statusCode: http.StatusBadRequest,
			headers:    http.Header{},
			qv:         url.Values{},
			resp:       &SampleData{Ok: "true"},
			err:        true,
		},
	}

	rec := &recorder{}
	serv := httptest.NewServer(rec)
	defer serv.Close()

	for _, test := range tests {
		rec.reset()
		rec.statusCode = test.statusCode
		rec.ret = test.resp

		comm := New(serv.Client())
		err := comm.JSONCall(context.Background(), serv.URL, test.headers, test.qv, test.body, test.resp)
		switch {
		case err == nil && test.err:
			t.Errorf("TestJSONCall(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestJSONCall(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if test.expectMethod != rec.gotMethod {
			t.Errorf("TestJSONCall(%s): got method == %s, want http method == %s", test.desc, test.expectMethod, rec.gotMethod)
			continue
		}

		if diff := pretty.Compare(test.qv, rec.gotQV); diff != "" {
			t.Errorf("TestJSONCall(%s): query values: -want/+got:\n%s", test.desc, diff)
			continue
		}

		if test.expectHeaders != nil {
			if diff := pretty.Compare(test.expectHeaders, rec.gotHeaders); diff != "" {
				t.Errorf("TestJSONCall(%s): headers: -want/+got:\n%s", test.desc, diff)
				continue
			}
		}

		if test.expectBody != nil {
			gotBody := SampleData{}
			if err := json.Unmarshal(rec.gotBody, &gotBody); err != nil {
				panic(err)
			}
			if diff := pretty.Compare(test.expectBody, gotBody); diff != "" {
				t.Errorf("TestJSONCall(%s): body: -want/+got:\n%s", test.desc, diff)
				continue
			}
		}

		if diff := pretty.Compare(test.want, test.resp); diff != "" {
			t.Errorf("TestJSONCall(%s): result: -want/+got:\n%s", test.desc, diff)
		}
	}
}

func TestXMLCall(t *testing.T) {
	tests := []struct {
		desc       string
		statusCode int
		headers    http.Header
		qv         url.Values
		resp       interface{}

		expectHeaders http.Header
		expectBody    interface{}

		want interface{}
		err  bool
	}{
		{
			desc:       "Error: non-struct resp value",
			statusCode: http.StatusOK,
			resp:       new(int),
			err:        true,
		},
		{
			desc:       "Error: non-pointer resp value",
			statusCode: http.StatusOK,
			resp:       SampleData{},
			err:        true,
		},
		{
			desc:       "Success",
			statusCode: http.StatusOK,
			headers:    http.Header{"header": []string{"here"}},
			qv:         url.Values{"key": []string{"value"}},
			resp:       &SampleData{Ok: "true"},
			expectHeaders: addStdHeaders(
				http.Header{
					"Header":       []string{"here"},
					"Content-Type": []string{"application/xml; charset=utf-8"},
				},
			),
			want: &SampleData{Ok: "true"},
		},
		{
			desc:       "Error: non-200 response",
			statusCode: http.StatusBadRequest,
			headers:    http.Header{},
			qv:         url.Values{},
			resp:       &SampleData{Ok: "true"},
			err:        true,
		},
	}

	rec := &recorder{xml: true}
	serv := httptest.NewServer(rec)
	defer serv.Close()

	for _, test := range tests {
		rec.reset()
		rec.statusCode = test.statusCode
		rec.ret = test.resp

		comm := New(serv.Client())
		err := comm.XMLCall(context.Background(), serv.URL, test.headers, test.qv, test.resp)
		switch {
		case err == nil && test.err:
			t.Errorf("TestXMLCall(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestXMLCall(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if rec.gotMethod != http.MethodGet {
			t.Errorf("TestXMLCall(%s): got method == %s, want http method == GET", test.desc, rec.gotMethod)
			continue
		}

		if diff := pretty.Compare(test.qv, rec.gotQV); diff != "" {
			t.Errorf("TestXMLCall(%s): query values: -want/+got:\n%s", test.desc, diff)
			continue
		}

		if test.expectHeaders != nil {
			if diff := pretty.Compare(test.expectHeaders, rec.gotHeaders); diff != "" {
				t.Errorf("TestXMLCall(%s): headers: -want/+got:\n%s", test.desc, diff)
				continue
			}
		}

		if test.expectBody != nil {
			gotBody := SampleData{}
			if err := xml.Unmarshal(rec.gotBody, &gotBody); err != nil {
				panic(err)
			}
			if diff := pretty.Compare(test.expectBody, gotBody); diff != "" {
				t.Errorf("TestXMLCall(%s): body: -want/+got:\n%s", test.desc, diff)
				continue
			}
		}

		if diff := pretty.Compare(test.want, test.resp); diff != "" {
			t.Errorf("TestXMLCall(%s): result: -want/+got:\n%s", test.desc, diff)
		}
	}
}

func TestSoapCall(t *testing.T) {
	const soapActionDefault = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
	req := SampleData{Ok: "whatever"}
	body, err := xml.Marshal(req)
	if err != nil {
		panic(err)
	}

	tests := []struct {
		desc       string
		statusCode int
		action     string
		body       string
		headers    http.Header
		qv         url.Values
		resp       interface{}

		expectHeaders http.Header
		expectBody    interface{}

		want interface{}
		err  bool
	}{
		{
			desc:       "Error: non-struct resp value",
			statusCode: http.StatusOK,
			resp:       new(int),
			err:        true,
		},
		{
			desc:       "Error: non-pointer resp value",
			statusCode: http.StatusOK,
			resp:       SampleData{},
			err:        true,
		},
		{
			desc:       "Error: body arg was empty string",
			statusCode: http.StatusOK,
			action:     soapActionDefault,
			headers:    http.Header{"header": []string{"here"}},
			qv:         url.Values{"key": []string{"value"}},
			resp:       &SampleData{Ok: "true"},
			err:        true,
		},
		{
			desc:       "Success",
			statusCode: http.StatusOK,
			headers:    http.Header{"header": []string{"here"}},
			qv:         url.Values{"key": []string{"value"}},
			action:     soapActionDefault,
			body:       string(body),
			resp:       &SampleData{Ok: "true"},
			expectHeaders: addStdHeaders(
				http.Header{
					"Header":       []string{"here"},
					"Content-Type": []string{"application/soap+xml; charset=utf-8"},
					"Soapaction":   []string{soapActionDefault},
				},
			),
			want: &SampleData{Ok: "true"},
		},
		{
			desc:       "Error: non-200 response",
			statusCode: http.StatusBadRequest,
			headers:    http.Header{},
			qv:         url.Values{},
			resp:       &SampleData{Ok: "true"},
			err:        true,
		},
	}

	rec := &recorder{xml: true}
	serv := httptest.NewServer(rec)
	defer serv.Close()

	for _, test := range tests {
		rec.reset()
		rec.statusCode = test.statusCode
		rec.ret = test.resp

		comm := New(serv.Client())
		err := comm.SOAPCall(context.Background(), serv.URL, test.action, test.headers, test.qv, test.body, test.resp)
		switch {
		case err == nil && test.err:
			t.Errorf("TestXMLCall(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestXMLCall(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if rec.gotMethod != http.MethodPost {
			t.Errorf("TestXMLCall(%s): got method == %s, want http method == POST", test.desc, rec.gotMethod)
			continue
		}

		if diff := pretty.Compare(test.qv, rec.gotQV); diff != "" {
			t.Errorf("TestXMLCall(%s): query values: -want/+got:\n%s", test.desc, diff)
			continue
		}

		if test.expectHeaders != nil {
			if diff := pretty.Compare(test.expectHeaders, rec.gotHeaders); diff != "" {
				t.Errorf("TestXMLCall(%s): headers: -want/+got:\n%s", test.desc, diff)
				continue
			}
		}

		if test.expectBody != nil {
			gotBody := SampleData{}
			if err := xml.Unmarshal(rec.gotBody, &gotBody); err != nil {
				panic(err)
			}
			if diff := pretty.Compare(test.expectBody, gotBody); diff != "" {
				t.Errorf("TestXMLCall(%s): body: -want/+got:\n%s", test.desc, diff)
				continue
			}
		}

		if diff := pretty.Compare(test.want, test.resp); diff != "" {
			t.Errorf("TestXMLCall(%s): result: -want/+got:\n%s", test.desc, diff)
		}
	}
}

func TestURLFormCall(t *testing.T) {
	tests := []struct {
		desc       string
		statusCode int
		action     string
		body       string
		headers    http.Header
		qv         url.Values
		resp       interface{}

		expectHeaders  http.Header
		expectEndpoint string

		want interface{}
		err  bool
	}{
		{
			desc:       "Error: non-struct resp value",
			statusCode: http.StatusOK,
			resp:       new(int),
			err:        true,
		},
		{
			desc:       "Error: non-pointer resp value",
			statusCode: http.StatusOK,
			resp:       SampleData{},
			err:        true,
		},
		{
			desc:       "Error: empty query values",
			statusCode: http.StatusOK,
			headers:    http.Header{"header": []string{"here"}},
			resp:       &SampleData{Ok: "true"},
			expectHeaders: addStdHeaders(
				http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded; charset=utf-8"},
				},
			),
			err: true,
		},
		{
			desc:       "Success",
			statusCode: http.StatusOK,
			headers:    http.Header{"header": []string{"here"}},
			qv:         url.Values{"key": []string{"value"}},
			resp:       &SampleData{Ok: "true"},
			expectHeaders: addStdHeaders(
				http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded; charset=utf-8"},
				},
			),
			want: &SampleData{Ok: "true"},
		},
		{
			desc:       "Error: non-200 response",
			statusCode: http.StatusBadRequest,
			headers:    http.Header{"header": []string{"here"}},
			qv:         url.Values{"key": []string{"value"}},
			resp:       &SampleData{Ok: "true"},
			err:        true,
		},
	}

	rec := &recorder{}
	serv := httptest.NewServer(rec)
	defer serv.Close()

	for _, test := range tests {
		rec.reset()
		rec.statusCode = test.statusCode
		rec.ret = test.resp

		comm := New(serv.Client())
		err := comm.URLFormCall(context.Background(), serv.URL, test.qv, test.resp)
		switch {
		case err == nil && test.err:
			t.Errorf("TestURLFormCall(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestURLFormCall(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if rec.gotMethod != http.MethodPost {
			t.Errorf("TestURLFormCall(%s): got method == %s, want http method == POST", test.desc, rec.gotMethod)
			continue
		}

		if test.expectHeaders != nil {
			if diff := pretty.Compare(test.expectHeaders, rec.gotHeaders); diff != "" {
				t.Errorf("TestURLFormCall(%s): headers: -want/+got:\n%s", test.desc, diff)
				continue
			}
		}

		want := test.qv.Encode()
		got := string(rec.gotBody)
		if diff := diff.Diff(want, got); diff != "" {
			t.Errorf("TestXMLCall(%s): body: -want/+got:\n%s", test.desc, diff)
			continue
		}

		if diff := pretty.Compare(test.want, test.resp); diff != "" {
			t.Errorf("TestXMLCall(%s): result: -want/+got:\n%s", test.desc, diff)
		}
	}
}
