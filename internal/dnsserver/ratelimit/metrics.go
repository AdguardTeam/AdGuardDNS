package ratelimit

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/miekg/dns"
)

// MetricsListener is an interface that is used for monitoring the
// ratelimit.Middleware state.  The middleware user may opt to supply a metrics
// interface implementation that would increment different kinds of metrics
// (for instance, prometheus metrics).
type MetricsListener interface {
	// OnRateLimited is called when the DNS query is dropped.
	OnRateLimited(ctx context.Context, req *dns.Msg, rw dnsserver.ResponseWriter)

	// OnAllowlisted is called when the DNS query is allowlisted.
	OnAllowlisted(ctx context.Context, req *dns.Msg, rw dnsserver.ResponseWriter)
}

// EmptyMetricsListener implements MetricsListener with empty functions.
// This implementation is used by default if the user does not supply a custom
// one.
type EmptyMetricsListener struct{}

// type check
var _ MetricsListener = (*EmptyMetricsListener)(nil)

// OnRateLimited implements the MetricsListener interface for
// *EmptyMetricsListener.
func (e *EmptyMetricsListener) OnRateLimited(context.Context, *dns.Msg, dnsserver.ResponseWriter) {
	// do nothing
}

// OnAllowlisted implements the MetricsListener interface for
// *EmptyMetricsListener.
func (e *EmptyMetricsListener) OnAllowlisted(context.Context, *dns.Msg, dnsserver.ResponseWriter) {
	// do nothing
}
