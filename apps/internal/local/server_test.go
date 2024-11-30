// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package local

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
)

func TestServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tests := []struct {
		desc                  string
		reqState              string
		port                  int
		q                     url.Values
		failPage              bool
		statusCode            int
		successPage           []byte
		errorPage             []byte
		testTemplate          bool
		testErrCodeXSS        bool
		testErrDescriptionXSS bool
		expected              string
	}{
		{
			desc:       "Error: Query Values has 'error' key",
			reqState:   "state",
			port:       0,
			q:          url.Values{"state": []string{"state"}, "error": []string{"error"}},
			statusCode: 200,
			failPage:   true,
		},
		{
			desc:       "Error: Query Values missing 'state' key",
			reqState:   "state",
			port:       0,
			q:          url.Values{"code": []string{"code"}},
			statusCode: http.StatusInternalServerError,
		},
		{
			desc:       "Error: Query Values missing had 'state' key value that was different that requested",
			reqState:   "state",
			port:       0,
			q:          url.Values{"state": []string{"etats"}, "code": []string{"code"}},
			statusCode: http.StatusInternalServerError,
		},
		{
			desc:       "Error: Query Values missing 'code' key",
			reqState:   "state",
			port:       0,
			q:          url.Values{"state": []string{"state"}},
			statusCode: http.StatusInternalServerError,
		},
		{
			desc:       "Success",
			reqState:   "state",
			port:       0,
			q:          url.Values{"state": []string{"state"}, "code": []string{"code"}},
			statusCode: 200,
		},
		{
			desc:         "Error: Query Values missing 'state' key, and optional error page, with template having code and error",
			reqState:     "state",
			port:         0,
			q:            url.Values{"error": []string{"error_code"}, "error_description": []string{"error_description"}},
			statusCode:   200,
			errorPage:    []byte("test option error page {{.Code}} {{.Err}}"),
			testTemplate: true,
			expected:     "test option error page error_code error_description",
		},
		{
			desc:         "Error: Query Values missing 'state' key, and optional error page, with template having only code",
			reqState:     "state",
			port:         0,
			q:            url.Values{"error": []string{"error_code"}, "error_description": []string{"error_description"}},
			statusCode:   200,
			errorPage:    []byte("test option error page {{.Code}}"),
			testTemplate: true,
			expected:     "test option error page error_code",
		},
		{
			desc:         "Error: Query Values missing 'state' key, and optional error page, with template having only error",
			reqState:     "state",
			port:         0,
			q:            url.Values{"error": []string{"error_code"}, "error_description": []string{"error_description"}},
			statusCode:   200,
			errorPage:    []byte("test option error page {{.Err}}"),
			testTemplate: true,
			expected:     "test option error page error_description",
		},
		{
			desc:         "Error: Query Values missing 'state' key, and optional error page, having no code or error",
			reqState:     "state",
			port:         0,
			q:            url.Values{"error": []string{"error_code"}, "error_description": []string{"error_description"}},
			statusCode:   200,
			errorPage:    []byte("test option error page"),
			testTemplate: true,
			expected:     "test option error page",
		},
		{
			desc:         "Error: Query Values missing 'state' key, using default fail error page",
			reqState:     "state",
			port:         0,
			q:            url.Values{"error": []string{"error_code"}, "error_description": []string{"error_description"}},
			statusCode:   200,
			testTemplate: true,
			expected:     "<p>Error details: error error_code, error description: error_description</p>",
		},
		{
			desc:           "Error: Query Values missing 'state' key, using default fail error page - Error Code XSS test",
			reqState:       "state",
			port:           0,
			q:              url.Values{"error": []string{"<script>alert('this code snippet was executed')</script>"}, "error_description": []string{"error_description"}},
			statusCode:     200,
			testTemplate:   true,
			testErrCodeXSS: true,
		},
		{
			desc:                  "Error: Query Values missing 'state' key, using default fail error page - Error Description XSS test",
			reqState:              "state",
			port:                  0,
			q:                     url.Values{"error": []string{"error_code"}, "error_description": []string{"<script>alert('this code snippet was executed')</script>"}},
			statusCode:            200,
			testTemplate:          true,
			testErrDescriptionXSS: true,
		},
		{
			desc:           "Error: Query Values missing 'state' key, using optional fail error page - Error Code XSS test",
			reqState:       "state",
			port:           0,
			q:              url.Values{"error": []string{"<script>alert('this code snippet was executed')</script>"}, "error_description": []string{"error_description"}},
			statusCode:     200,
			errorPage:      []byte("error: {{.Code}} error_description: {{.Err}}"),
			testTemplate:   true,
			testErrCodeXSS: true,
			expected:       "&lt;script&gt;alert(&#39;this code snippet was executed&#39;)&lt;/script&gt;",
		},
		{
			desc:                  "Error: Query Values missing 'state' key, using optional fail error page - Error Description XSS test",
			reqState:              "state",
			port:                  0,
			q:                     url.Values{"error": []string{"error_code"}, "error_description": []string{"<script>alert('this code snippet was executed')</script>"}},
			statusCode:            200,
			errorPage:             []byte("error: {{.Code}} error_description: {{.Err}}"),
			testTemplate:          true,
			testErrDescriptionXSS: true,
			expected:              "&lt;script&gt;alert(&#39;this code snippet was executed&#39;)&lt;/script&gt;",
		},
	}

	for _, test := range tests {
		serv, err := New(test.reqState, test.port, test.successPage, test.errorPage)
		if err != nil {
			panic(err)
		}
		defer serv.Shutdown()

		if !strings.HasPrefix(serv.Addr, "http://localhost") {
			t.Fatalf("unexpected server address %s", serv.Addr)
		}
		u, err := url.Parse(serv.Addr)
		if err != nil {
			panic(err)
		}
		u.RawQuery = test.q.Encode()

		resp, err := http.DefaultClient.Do(
			&http.Request{
				Method: "GET",
				URL:    u,
			},
		)

		if err != nil {
			panic(err)
		}

		if resp.StatusCode != test.statusCode {
			if test.statusCode == 200 {
				t.Errorf("TestServer(%s): got StatusCode == %d, want StatusCode == 200", test.desc, resp.StatusCode)
				res := serv.Result(ctx)
				if res.Err == nil {
					t.Errorf("TestServer(%s): Result.Err == nil, want Result.Err != nil", test.desc)
				}
				continue
			}
			t.Errorf("TestServer(%s): got StatusCode == %d, want StatusCode == %d", test.desc, resp.StatusCode, test.statusCode)
			res := serv.Result(ctx)
			if res.Err == nil {
				t.Errorf("TestServer(%s): Result.Err == nil, want Result.Err != nil", test.desc)
			}
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		if test.failPage {
			if !strings.Contains(string(content), "Authentication Failed") {
				t.Errorf("TestServer(%s): got okay page, want failed page", test.desc)
			}

			res := serv.Result(ctx)
			if res.Err == nil {
				t.Errorf("TestServer(%s): Result.Err == nil, want Result.Err != nil", test.desc)
			}
			continue
		}

		if len(test.successPage) > 0 {
			if !bytes.Equal(content, test.successPage) {
				t.Errorf("TestServer(%s): -want/+got:\ntest option error page", test.desc)
			}
			continue
		}

		if test.testTemplate {
			if test.testErrCodeXSS || test.testErrDescriptionXSS {
				if !strings.Contains(string(content), test.expected) {
					t.Errorf("TestServer(%s): want escaped html entities", test.desc)
				}
				continue
			}

			if len(test.errorPage) > 0 && (test.testErrCodeXSS || test.testErrDescriptionXSS) {
				if !strings.Contains(string(content), test.expected) {
					t.Errorf("TestServer(%s): want escaped html entities", test.desc)
				}
				continue
			}

			if len(test.errorPage) > 0 {
				errCode := bytes.Contains(test.errorPage, []byte("{{.Code}}"))
				errDescription := bytes.Contains(test.errorPage, []byte("{{.Err}}"))

				if !errCode && !errDescription {
					if !strings.Contains(string(content), test.expected) {
						t.Errorf("TestServer(%s): -want/+got:\ntest option error page", test.desc)
					}
				}
				if errCode && errDescription {
					if !strings.Contains(string(content), test.expected) {
						t.Errorf("TestServer(%s): -want/+got:\ntest option error page error_code error_description", test.desc)
					}
				}
				if errCode && !errDescription {
					if !strings.Contains(string(content), test.expected) {
						t.Errorf("TestServer(%s): -want/+got:\ntest option error page error_code", test.desc)
					}
				}
				if !errCode && errDescription {
					if !strings.Contains(string(content), test.expected) {
						t.Errorf("TestServer(%s): -want/+got:\ntest option error page error_description", test.desc)
					}
				}
				continue
			} else {
				if !strings.Contains(string(content), test.expected) {
					t.Errorf("TestServer(%s): -want/+got:\ntest option error page error_code error_description", test.desc)
				}
				continue
			}
		}

		if !strings.Contains(string(content), "Authentication Complete") {
			t.Errorf("TestServer(%s): got failed page, okay page", test.desc)
		}

		res := serv.Result(ctx)
		if diff := pretty.Compare(Result{Code: "code"}, res); diff != "" {
			t.Errorf("TestServer(%s): -want/+got:\n%s", test.desc, diff)
		}
	}
}
