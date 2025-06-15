package websvc

import (
	"context"
)

// RequestType is a type alias for string that represents the request type
// for web service metrics.
type RequestType = string

// List of web service requests of type RequestType.
//
// NOTE:  Keep in sync with [metrics.RequestType].
const (
	RequestTypeError404            RequestType = "error404"
	RequestTypeError500            RequestType = "error500"
	RequestTypeStaticContent       RequestType = "static_content"
	RequestTypeDNSCheckTest        RequestType = "dnscheck_test"
	RequestTypeRobotsTxt           RequestType = "robots_txt"
	RequestTypeRootRedirect        RequestType = "root_redirect"
	RequestTypeLinkedIPProxy       RequestType = "linkip"
	RequestTypeAdultBlockingPage   RequestType = "adult_blocking_page"
	RequestTypeGeneralBlockingPage RequestType = "general_blocking_page"
	RequestTypeSafeBrowsingPage    RequestType = "safe_browsing_page"
)

// Metrics is an interface for collecting web service request statistics.
type Metrics interface {
	// IncrementReqCount increments the web service request count for a given
	// RequestType.  reqType must be one of the RequestType values.
	IncrementReqCount(ctx context.Context, reqType RequestType)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementReqCount implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementReqCount(_ context.Context, _ RequestType) {}
