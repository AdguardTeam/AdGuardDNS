package forward

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// Common Errors

// Error is the forwarding error.
type Error struct {
	Err      error
	Upstream Upstream
}

// type check
var _ error = (*Error)(nil)

// Error implements the error interface for *Error.
func (err *Error) Error() (msg string) {
	return fmt.Sprintf("forwarding to %s: %s", err.Upstream, err.Err)
}

// type check
var _ errors.Wrapper = (*Error)(nil)

// Unwrap implements the errors.Wrapper interface for *Error.
func (err *Error) Unwrap() (unwrapped error) {
	return err.Err
}

// annotate is a deferrable helper for forwarding errors.
func annotate(err error, ups Upstream) (wrapped error) {
	if err == nil {
		return nil
	}

	return &Error{
		Err:      err,
		Upstream: ups,
	}
}
