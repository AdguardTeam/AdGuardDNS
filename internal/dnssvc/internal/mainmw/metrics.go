package mainmw

import (
	"context"
	"net/netip"
	"time"
)

// Metrics is an interface for collection of the statistics of the main
// filtering middleware.
type Metrics interface {
	// OnRequest records the request metrics.  m must not be nil.
	OnRequest(ctx context.Context, m *RequestMetrics)
}

// RequestMetrics is an alias for a structure that contains the information
// about a request that has reached the filtering middleware.
//
// NOTE:  This is an alias to reduce the amount of dependencies required of
// implementations.  This is also the reason why only built-in or stdlib types
// are used.
type RequestMetrics = struct {
	// RemoteIP is the IP address of the client.
	RemoteIP netip.Addr

	// Continent is the continent code, if any.
	Continent string

	// Country is the country code, if any.
	Country string

	// FilterListID is the ID of the filtering-rule list affecting this query,
	// if any.
	FilterListID string

	// FilteringDuration is the total amount of time spent filtering the query.
	FilteringDuration time.Duration

	// ASN is the autonomous-system number, if any.
	ASN uint32

	// IsAnonymous is true if the request does not have a profile associated
	// with it.
	IsAnonymous bool

	// IsBlocked is true if the request is blocked or rewritten.
	IsBlocked bool
}

// EmptyMetrics is an implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// OnRequest implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) OnRequest(_ context.Context, _ *RequestMetrics) {}
