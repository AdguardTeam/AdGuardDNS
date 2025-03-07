package dnscheck

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/consulkv"
	"github.com/AdguardTeam/golibs/errors"
)

// Error types for [Metrics.HandleError].
const (
	errMtrcTypeTimeout   = "timeout"
	errMtrcTypeRatelimit = "ratelimit"
	errMtrcTypeOther     = "other"
)

// Request types for [Metrics].
const (
	reqMtrcTypeDNS  = "dns"
	reqMtrcTypeHTTP = "http"
)

// Metrics is an interface that is used for the collection of the DNSCheck
// service statistics.
type Metrics interface {
	// HandleError handles the total number of errors by type.  reqType must be
	// [reqMtrcTypeDNS] or [reqMtrcTypeHTTP].  errType must be either
	// [errMtrcTypeTimeout], [errMtrcTypeRatelimit], [errMtrcTypeOther] or an
	// empty string.
	HandleError(ctx context.Context, reqType, errType string)

	// HandleRequest handles the total number of requests by type.  reqType must
	// be [reqMtrcTypeDNS] or [reqMtrcTypeHTTP].
	HandleRequest(ctx context.Context, reqType string, isValid bool)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// HandleError implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) HandleError(_ context.Context, _, _ string) {}

// HandleRequest implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) HandleRequest(_ context.Context, _ string, _ bool) {}

// errMetricsType returns the error type for [Metrics.HandleError].  It is an
// empty string if there is no error.
func errMetricsType(err error) (errType string) {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return errMtrcTypeTimeout
	case errors.Is(err, consulkv.ErrRateLimited):
		return errMtrcTypeRatelimit
	default:
		return errMtrcTypeOther
	}
}
