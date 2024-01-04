package dnscheck

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
)

// errRateLimited is returned by [Consul.info] when the request is rate limited.
const errRateLimited errors.Error = "rate limited"

// httpKVError is an error returned by the Consul KV database HTTP client.
type httpKVError struct {
	err error
}

// type check
var _ error = httpKVError{}

// Error implements the error interface for httpKVError.
func (err httpKVError) Error() (msg string) {
	return err.err.Error()
}

// type check
var _ errors.Wrapper = httpKVError{}

// Unwrap implements the [errors.Wrapper] interface for httpKVError.
func (err httpKVError) Unwrap() (unwrapped error) {
	return err.err
}

// type check
var _ errcoll.SentryReportableError = httpKVError{}

// IsSentryReportable implements the [errcoll.SentryReportableError] interface
// for httpKVError.
func (err httpKVError) IsSentryReportable() (ok bool) {
	return !errors.Is(err.err, errRateLimited) &&
		!errors.Is(err.err, context.Canceled) &&
		!errors.Is(err.err, context.DeadlineExceeded)
}

// incErrMetrics increments error gauge metrics for the given src and err.
// "source" can be "dns" or "http".
func incErrMetrics(src string, err error) {
	if err == nil {
		return
	}

	var errType string
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		errType = "timeout"
	case errors.Is(err, errRateLimited):
		errType = "ratelimit"
	default:
		errType = "other"
	}

	metrics.DNSCheckErrorTotal.WithLabelValues(src, errType).Inc()
}
