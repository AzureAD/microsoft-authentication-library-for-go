package errors

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/kylelemons/godebug/pretty"
)

var prettyConf = &pretty.Config{IncludeUnexported: false, SkipZeroFields: true, TrackCycles: true}

type verboser interface {
	Verbose() string
}

// Verbose prints the most verbose error that the error message has.
func Verbose(err error) string {
	if v, ok := err.(verboser); ok {
		log.Println("VERBOSE ERROR")
		return v.Verbose()
	}
	log.Printf("NOT VERBOSE ERROR: %T", err)
	return err.Error()
}

// New is equivalent to errors.New().
func New(text string) error {
	return errors.New(text)
}

// CallErr represents an HTTP call error. Has a Verbose() method that allows getting the
// http.Request and Response objects. Implements error.
type CallErr struct {
	Req  *http.Request
	Resp *http.Response
	Err  error
}

// Errors implements error.Error().
func (e CallErr) Error() string {
	return e.Err.Error()
}

// Verbose prints a versbose error message with the request or response.
func (e CallErr) Verbose() string {
	return fmt.Sprintf("%s:\n\tRequest:\n%s\n\tResponse:\n%s", e.Err, prettyConf.Sprint(e.Req), prettyConf.Sprint(e.Resp))
}
