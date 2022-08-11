// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package local

import (
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
		desc       string
		reqState   string
		port       int
		q          url.Values
		failPage   bool
		statusCode int
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
	}

	for _, test := range tests {
		serv, err := New(test.reqState, test.port)
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

		if !strings.Contains(string(content), "Authentication Complete") {
			t.Errorf("TestServer(%s): got failed page, okay page", test.desc)
		}

		res := serv.Result(ctx)
		if diff := pretty.Compare(Result{Code: "code"}, res); diff != "" {
			t.Errorf("TestServer(%s): -want/+got:\n%s", test.desc, diff)
		}
	}
}
