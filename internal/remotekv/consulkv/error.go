package consulkv

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
)

// ErrRateLimited is returned by [KV.Get] when the request is rate
// limited.
const ErrRateLimited errors.Error = "rate limited"

// httpError is an error returned by the Consul KV database HTTP client.
type httpError struct {
	err error
}

// type check
var _ error = httpError{}

// Error implements the error interface for httpError.
func (err httpError) Error() (msg string) {
	return err.err.Error()
}

// type check
var _ errors.Wrapper = httpError{}

// Unwrap implements the [errors.Wrapper] interface for httpError.
func (err httpError) Unwrap() (unwrapped error) {
	return err.err
}

// type check
var _ errcoll.SentryReportableError = httpError{}

// IsSentryReportable implements the [errcoll.SentryReportableError] interface
// for httpError.
func (err httpError) IsSentryReportable() (ok bool) {
	return !errors.Is(err.err, ErrRateLimited) &&
		!errors.Is(err.err, context.Canceled) &&
		!errors.Is(err.err, context.DeadlineExceeded)
}
