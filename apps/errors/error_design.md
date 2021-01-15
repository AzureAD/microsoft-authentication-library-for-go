# MSAL Error Design

Contributors:

- Joel Hendrix(jhendrix@microsoft.com)
- Keegan Caruso(Keegan.Caruso@microsoft.com)

Errors in MSAL are intended for app developers to troubleshoot and not for displaying to end-users.

Go chose not to have exceptions. Instead Go allows functions to return an error type in addition to a result via its support for multiple return values. By declaring a return value of the interface type error you indicate to the caller that this method could go wrong. I

## Client side errors

MSAL throws MsalClientException for things that go wrong inside the library (e.g. bad configuration)

All the equivalents of MSALClientExceptions are solved by throwing an on-the go error like this :

``` Go
return "", errors.New("authority does not have two segments")
```

## Service side errors

MSAL throws MsalServiceException for things that go wrong service side.

We already have a current existing implementation from the refactor which looks like this:

``` Go
// CallErr represents an HTTP call error. Has a Verbose() method that allows getting the
// http.Request and Response objects. Implements error.
type CallErr struct {
    Req  *http.Request
    Resp *http.Response
    Err  error
}
```

This implements the error interface in Go and the error method exposes the error response, if there exists one. A verbose error with the http request and the http response is also exposed using the Verbose function.
The error looks something like this:

``` Go
return nil, errors.CallErr{
    Req:  req,
    Resp: reply,
    Err:  fmt.Errorf("http call(%s)(%s) error: reply status code was %d:\n%s", req.URL.String(), req.Method, reply.StatusCode, ErrorResponse), //ErrorResponse is the json body extracted from the http response
    }
```
