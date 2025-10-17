// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package local contains a local HTTP server used with interactive authentication.
package local

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var okPage = []byte(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Authentication Complete</title>
</head>
<body>
    <p>Authentication complete. You can return to the application. Feel free to close this browser tab.</p>
</body>
</html>
`)

var failPage = []byte(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Authentication Failed</title>
</head>
<body>
	<p>Authentication failed. You can return to the application. Feel free to close this browser tab.</p>
	<p>Error details: error {{.Code}}, error description: {{.Err}}</p>
</body>
</html>
`)

var (
	// code is the html template variable name,
	// which matches the Result Code variable
	code = []byte("{{.Code}}")
	// err is the html template variable name
	// which matches the Result Err variable
	err = []byte("{{.Err}}")
)

// Result is the result from the redirect.
type Result struct {
	// Code is the code sent by the authority server.
	Code string
	// Err is set if there was an error.
	Err error
}

// Server is an HTTP server.
type Server struct {
	// Addr is the address the server is listening on.
	Addr        string
	resultCh    chan Result
	s           *http.Server
	reqState    string
	successPage []byte
	errorPage   []byte
}

// New creates a local HTTP server and starts it.
func New(reqState string, port int, successPage []byte, errorPage []byte) (*Server, error) {
	var l net.Listener
	var err error
	var portStr string
	if port > 0 {
		// use port provided by caller
		l, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
		portStr = strconv.FormatInt(int64(port), 10)
	} else {
		// find a free port
		for i := 0; i < 10; i++ {
			l, err = net.Listen("tcp", "localhost:0")
			if err != nil {
				continue
			}
			addr := l.Addr().String()
			portStr = addr[strings.LastIndex(addr, ":")+1:]
			break
		}
	}
	if err != nil {
		return nil, err
	}

	if len(successPage) == 0 {
		successPage = okPage
	}

	if len(errorPage) == 0 {
		errorPage = failPage
	}

	serv := &Server{
		Addr:        fmt.Sprintf("http://localhost:%s", portStr),
		s:           &http.Server{Addr: "localhost:0", ReadHeaderTimeout: time.Second},
		reqState:    reqState,
		resultCh:    make(chan Result, 1),
		successPage: successPage,
		errorPage:   errorPage,
	}
	serv.s.Handler = http.HandlerFunc(serv.handler)

	if err := serv.start(l); err != nil {
		return nil, err
	}

	return serv, nil
}

func (s *Server) start(l net.Listener) error {
	go func() {
		err := s.s.Serve(l)
		if err != nil {
			select {
			case s.resultCh <- Result{Err: err}:
			default:
			}
		}
	}()

	return nil
}

// Result gets the result of the redirect operation. Once a single result is returned, the server
// is shutdown. ctx deadline will be honored.
func (s *Server) Result(ctx context.Context) Result {
	select {
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	case r := <-s.resultCh:
		return r
	}
}

// Shutdown shuts down the server.
func (s *Server) Shutdown() {
	// Note: You might get clever and think you can do this in handler() as a defer, you can't.
	_ = s.s.Shutdown(context.Background())
}

func (s *Server) putResult(r Result) {
	select {
	case s.resultCh <- r:
	default:
	}
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	headerErr := q.Get("error")
	if headerErr != "" {
		// Note: It is a little weird we handle some errors by not going to the failPage. If they all should,
		// change this to s.error() and make s.error() write the failPage instead of an error code.

		escapedErrDesc := html.EscapeString(q.Get("error_description")) // provides XSS protection
		escapedHeaderErr := html.EscapeString(headerErr)                // provides XSS protection

		errorPage := bytes.ReplaceAll(s.errorPage, code, []byte(escapedHeaderErr))
		errorPage = bytes.ReplaceAll(errorPage, err, []byte(escapedErrDesc))

		_, _ = w.Write(errorPage)

		s.putResult(Result{Err: fmt.Errorf("%s", escapedErrDesc)})

		return
	}

	respState := q.Get("state")
	switch respState {
	case s.reqState:
	case "":
		s.error(w, http.StatusInternalServerError, "server didn't send OAuth state")
		return
	default:
		s.error(w, http.StatusInternalServerError, "mismatched OAuth state, req(%s), resp(%s)", s.reqState, respState)
		return
	}

	code := q.Get("code")
	if code == "" {
		s.error(w, http.StatusInternalServerError, "authorization code missing in query string")
		return
	}

	_, _ = w.Write(s.successPage)
	s.putResult(Result{Code: code})
}

func (s *Server) error(w http.ResponseWriter, code int, str string, i ...interface{}) {
	err := fmt.Errorf(str, i...)
	http.Error(w, err.Error(), code)
	s.putResult(Result{Err: err})
}
