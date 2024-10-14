package ratelimit

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/miekg/dns"
)

// Metrics is an interface for monitoring the [ratelimit.Middleware] state.  The
// middleware user may opt to supply a metrics interface implementation that
// would increment different kinds of metrics (for instance, Prometheus
// metrics).
type Metrics interface {
	// OnRateLimited is called when the DNS query is dropped.
	OnRateLimited(ctx context.Context, req *dns.Msg, rw dnsserver.ResponseWriter)

	// OnAllowlisted is called when the DNS query is allowlisted.
	OnAllowlisted(ctx context.Context, req *dns.Msg, rw dnsserver.ResponseWriter)
}

// EmptyMetrics implements [Metrics] with empty functions.  This implementation
// is used by default if the user does not supply a custom one.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// OnRateLimited implements the [Metrics] interface for *EmptyMetrics.
func (EmptyMetrics) OnRateLimited(context.Context, *dns.Msg, dnsserver.ResponseWriter) {}

// OnAllowlisted implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) OnAllowlisted(context.Context, *dns.Msg, dnsserver.ResponseWriter) {}
