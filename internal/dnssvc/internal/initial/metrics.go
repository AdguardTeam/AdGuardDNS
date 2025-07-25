package initial

import (
	"context"
)

// Request kinds for [Metrics].
const (
	// MetricsRequestKindDDR is a label for requests for Discovery of Designated
	// Resolvers.
	MetricsRequestKindDDR = "ddr"

	// MetricsRequestKindBadResolverARPA is a label for requests for malformed
	// resolver.arpa queries.
	MetricsRequestKindBadResolverARPA = "bad_resolver_arpa"

	// MetricsRequestKindChromePrefetch is a label for requests for the domain
	// name that Chrome uses to check if it should use its prefetch proxy.
	MetricsRequestKindChromePrefetch = "chrome_prefetch"

	// MetricsRequestKindFirefox is a label for requests for the domain name
	// that Firefox uses to check if it should use its own DNS-over-HTTPS
	// settings.
	MetricsRequestKindFirefox = "firefox"

	// MetricsRequestKindApplePrivateRelay is a label for requests for the
	// domain name that Apple devices use to check if Apple Private Relay can be
	// enabled.
	MetricsRequestKindApplePrivateRelay = "apple_private_relay"
)

// Metrics is an interface that is used for collection of statistics for DNS
// requests for special domain names.
type Metrics interface {
	// IncrementRequestsTotal increments the total number of DNS requests for
	// special domain names of the specified kind.  kind must be one of the
	// following: [MetricsRequestKindDDR], [MetricsRequestKindBadResolverARPA],
	// [MetricsRequestKindChromePrefetch], [MetricsRequestKindFirefox] or
	// [MetricsRequestKindApplePrivateRelay].
	IncrementRequestsTotal(ctx context.Context, kind string)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementRequestsTotal implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementRequestsTotal(_ context.Context, _ string) {}
