// Package plugin defines types to support creating plugins for the AdGuard DNS
// server.
package plugin

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
)

// Registry is a plugin registry that stores custom implementations of AdGuard
// DNS entities.  A nil Registry can be used safely: all its methods return zero
// values.
type Registry struct {
	dnscheck   dnscheck.Interface
	mainMwMtrc metrics.MainMiddleware
	postInitMw dnsserver.Middleware
}

// NewRegistry returns a new registry with the given custom implementations.
func NewRegistry(
	dnsCk dnscheck.Interface,
	mainMwMtrc metrics.MainMiddleware,
	postInitMw dnsserver.Middleware,
) (r *Registry) {
	return &Registry{
		dnscheck:   dnsCk,
		mainMwMtrc: mainMwMtrc,
		postInitMw: postInitMw,
	}
}

// DNSCheck returns a custom implementation of the DNSCheck service, if any.
func (r *Registry) DNSCheck() (dnsCk dnscheck.Interface) {
	if r == nil {
		return nil
	}

	return r.dnscheck
}

// MainMiddlewareMetrics returns a custom implementation of the
// filtering-middleware metrics, if any.
func (r *Registry) MainMiddlewareMetrics() (mainMwMtrc metrics.MainMiddleware) {
	if r == nil {
		return nil
	}

	return r.mainMwMtrc
}

// PostInitialMiddleware returns a custom implementation of the post-initial
// middleware, if any.
func (r *Registry) PostInitialMiddleware() (postInitMw dnsserver.Middleware) {
	if r == nil {
		return nil
	}

	return r.postInitMw
}
