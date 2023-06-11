package agdhttp

import (
	"fmt"
	"net/http"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
)

// Common HTTP Errors

// StatusError is returned by methods when the HTTP status code is different
// from the expected.
type StatusError struct {
	ServerName string
	Expected   int
	Got        int
}

// type check
var _ error = (*StatusError)(nil)

// Error implements the error interface for *StatusError.
func (err *StatusError) Error() (msg string) {
	return fmt.Sprintf(
		"server %q: status code error: expected %d, got %d",
		err.ServerName,
		err.Expected,
		err.Got,
	)
}

// CheckStatus returns a non-nil error with the data from resp if the status
// code in resp is not equal to expected.  resp must be non-nil.
//
// Any error returned will have the underlying type of *StatusError.
func CheckStatus(resp *http.Response, expected int) (err error) {
	if resp.StatusCode == expected {
		return nil
	}

	return &StatusError{
		ServerName: resp.Header.Get(httphdr.Server),
		Expected:   expected,
		Got:        resp.StatusCode,
	}
}

// ServerError is returned as general error in case header Server was specified.
type ServerError struct {
	Err        error
	ServerName string
}

// type check
var _ error = (*ServerError)(nil)

// Error implements the error interface for *ServerError.
func (err *ServerError) Error() (msg string) {
	return fmt.Sprintf("server %q: %s", err.ServerName, err.Err)
}

// type check
var _ errors.Wrapper = (*ServerError)(nil)

// Unwrap implements the errors.Wrapper interface for *ServerError.
func (err *ServerError) Unwrap() (unwrapped error) {
	return err.Err
}

// WrapServerError wraps err inside a *ServerError including data from resp.
// resp must not be nil.
func WrapServerError(err error, resp *http.Response) (wrapped *ServerError) {
	return &ServerError{
		Err:        err,
		ServerName: resp.Header.Get(httphdr.Server),
	}
}
