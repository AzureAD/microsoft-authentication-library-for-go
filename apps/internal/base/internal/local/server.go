// Package local contains a local HTTP server used with interactive authentication.
package local

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
)

const okPage = `
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
`

const failPage = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Authentication Failed</title>
</head>
<body>
	<p>Authentication failed. You can return to the application. Feel free to close this browser tab.</p>
	<p>Error details: error %s error_description: %s</p>
</body>
</html>
`

// Server is an HTTP server.
type Server struct {
	done chan struct{}
	s    *http.Server
	code string
	err  error
}

// NewServer creates a local HTTP server.
func NewServer() *Server {
	rs := &Server{
		done: make(chan struct{}),
		s:    &http.Server{},
	}
	return rs
}

// Start starts the local HTTP server on a separate go routine.
// The return value is the full URL plus port number.
func (s *Server) Start(reqState string) string {
	port := rand.Intn(600) + 8400
	s.s.Addr = fmt.Sprintf(":%d", port)
	s.s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			s.done <- struct{}{}
		}()
		qp := r.URL.Query()
		if respState, ok := qp["state"]; !ok {
			s.err = errors.New("missing OAuth state")
			return
		} else if respState[0] != reqState {
			s.err = errors.New("mismatched OAuth state")
			return
		}
		if err, ok := qp["error"]; ok {
			desc := qp.Get("error_description")
			w.Write([]byte(fmt.Sprintf(failPage, err[0], desc)))
			s.err = fmt.Errorf("authentication error: %s; description: %s", err[0], desc)
			return
		}
		if code, ok := qp["code"]; ok {
			w.Write([]byte(okPage))
			s.code = code[0]
		} else {
			s.err = errors.New("authorization code missing in query string")
		}
	})
	go s.s.ListenAndServe()
	return fmt.Sprintf("http://localhost:%d", port)
}

// Stop will shut down the local HTTP server.
func (s *Server) Stop() {
	close(s.done)
	s.s.Shutdown(context.Background())
}

// WaitForCallback will wait until Azure interactive login has called us back with an authorization code or error.
func (s *Server) WaitForCallback(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AuthorizationCode returns the authorization code or error result from the interactive login.
func (s *Server) AuthorizationCode() (string, error) {
	return s.code, s.err
}
