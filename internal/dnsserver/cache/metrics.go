package cache

import (
	"context"

	"github.com/miekg/dns"
)

// MetricsListener is an interface that is used for monitoring the
// cache.Middleware state.  The middleware user may opt to supply a metrics
// interface implementation that would increment different kinds of metrics (for
// instance, prometheus metrics).
type MetricsListener interface {
	// OnCacheItemAdded is called when an item has been added to the cache.
	OnCacheItemAdded(ctx context.Context, resp *dns.Msg, cacheLen int)
	// OnCacheHit is called when a response for the specified request has been
	// found in the cache.
	OnCacheHit(ctx context.Context, req *dns.Msg)
	// OnCacheMiss is called when a response for the specified request has not
	// been found in the cache.
	OnCacheMiss(ctx context.Context, req *dns.Msg)
}

// EmptyMetricsListener implements MetricsListener with empty functions.  This
// implementation is used by default if the user does not supply a custom one.
type EmptyMetricsListener struct{}

// type check
var _ MetricsListener = EmptyMetricsListener{}

// OnCacheItemAdded implements the MetricsListener interface for
// EmptyMetricsListener.
func (EmptyMetricsListener) OnCacheItemAdded(_ context.Context, _ *dns.Msg, _ int) {}

// OnCacheHit implements the MetricsListener interface for EmptyMetricsListener.
func (EmptyMetricsListener) OnCacheHit(_ context.Context, _ *dns.Msg) {}

// OnCacheMiss implements the MetricsListener interface for
// EmptyMetricsListener.
func (EmptyMetricsListener) OnCacheMiss(_ context.Context, _ *dns.Msg) {}
