package ratelimitmw

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/miekg/dns"
)

// Metrics is an interface for monitoring the [ratelimitmw.Middleware] state.
type Metrics interface {
	ratelimit.Metrics

	// IncrementAccessBlockedByHost is called when the DNS request is blocked by
	// host.
	IncrementAccessBlockedByHost(ctx context.Context)

	// IncrementAccessBlockedByProfile is called when the DNS request is blocked
	// by a profile's access settings.
	IncrementAccessBlockedByProfile(ctx context.Context)

	// IncrementAccessBlockedBySubnet is called when the DNS request is blocked
	// by subnet.
	IncrementAccessBlockedBySubnet(ctx context.Context)

	// IncrementRatelimitedByProfile is called when the DNS request is dropped
	// by a profile's ratelimit settings.
	IncrementRatelimitedByProfile(ctx context.Context)

	// IncrementUnknownDedicated is called when the DNS request is sent to an
	// unknown local address.
	IncrementUnknownDedicated(ctx context.Context)
}

// EmptyMetrics is an empty [Metrics] implementation that does nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementAccessBlockedByHost implements the [Metrics] interface for
// *EmptyMetrics.
func (EmptyMetrics) IncrementAccessBlockedByHost(_ context.Context) {}

// IncrementAccessBlockedByProfile implements the [Metrics] interface for
// *EmptyMetrics.
func (EmptyMetrics) IncrementAccessBlockedByProfile(_ context.Context) {}

// IncrementAccessBlockedBySubnet implements the [Metrics] interface for
// *EmptyMetrics.
func (EmptyMetrics) IncrementAccessBlockedBySubnet(_ context.Context) {}

// IncrementRatelimitedByProfile implements the [Metrics] interface for
// *EmptyMetrics.
func (EmptyMetrics) IncrementRatelimitedByProfile(_ context.Context) {}

// IncrementUnknownDedicated implements the [Metrics] interface for
// *EmptyMetrics.
func (EmptyMetrics) IncrementUnknownDedicated(_ context.Context) {}

// OnAllowlisted implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) OnAllowlisted(_ context.Context, _ *dns.Msg, _ dnsserver.ResponseWriter) {}

// OnRateLimited implements the [Metrics] interface for *EmptyMetrics.
func (EmptyMetrics) OnRateLimited(_ context.Context, _ *dns.Msg, _ dnsserver.ResponseWriter) {}
