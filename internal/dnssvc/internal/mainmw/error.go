package mainmw

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
)

// afterFilteringError is returned by the handler function of [Middleware.Wrap]
// in case there is an error after filtering.
type afterFilteringError struct {
	err error
}

// type check
var _ error = afterFilteringError{}

// Error implements the error interface for afterFilteringError.
func (err afterFilteringError) Error() (msg string) {
	return fmt.Sprintf("after filtering: %s", err.err)
}

// type check
var _ errors.Wrapper = afterFilteringError{}

// Unwrap implements the [errors.Wrapper] interface for afterFilteringError.
func (err afterFilteringError) Unwrap() (unwrapped error) {
	return err.err
}

// type check
var _ errcoll.SentryReportableError = afterFilteringError{}

// IsSentryReportable implements the [errcoll.SentryReportableError] interface
// for afterFilteringError.
func (err afterFilteringError) IsSentryReportable() (ok bool) {
	return !errors.Is(err.err, context.DeadlineExceeded) &&
		!errors.Is(err.err, context.Canceled)
}
