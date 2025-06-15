// Package plugin defines types to support creating plugins for the AdGuard DNS
// server.
package plugin

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/golibs/service"
)

// Config is the configuration structure for the plugin registry.
type Config struct {
	// DNSCheck is a custom implementation of the DNSCheck service.
	DNSCheck dnscheck.Interface

	// MainMwMtrc is a custom implementation of the filtering-middleware
	// metrics.
	MainMwMtrc metrics.MainMiddleware

	// PostInitMw is a custom implementation of the post-initial middleware.
	PostInitMw dnsserver.Middleware

	// RuleStat is a custom implementation of the statistics service.
	RuleStat rulestat.Interface

	// Refreshers is a map of refreshers to be added to the debug refreshers.
	// The keys of the map are the refreshers identifiers.
	Refreshers map[string]service.Refresher

	// Services is a map of services to be started.  The keys of the map are the
	// services identifiers.
	Services map[string]service.Interface
}

// Registry is a plugin registry that stores custom implementations of AdGuard
// DNS entities.  A nil Registry can be used safely: all its methods return zero
// values.
type Registry struct {
	dnscheck   dnscheck.Interface
	mainMwMtrc metrics.MainMiddleware
	postInitMw dnsserver.Middleware
	ruleStat   rulestat.Interface
	refrs      map[string]service.Refresher
	svcs       map[string]service.Interface
}

// NewRegistry returns a new registry with the given custom implementations.  c
// must not be nil.
func NewRegistry(c *Config) (r *Registry) {
	return &Registry{
		dnscheck:   c.DNSCheck,
		mainMwMtrc: c.MainMwMtrc,
		postInitMw: c.PostInitMw,
		ruleStat:   c.RuleStat,
		refrs:      c.Refreshers,
		svcs:       c.Services,
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

// RuleStat returns a custom implementation of the [rulestat.Interface] service,
// if any.
func (r *Registry) RuleStat() (ruleStat rulestat.Interface) {
	if r == nil {
		return nil
	}

	return r.ruleStat
}

// Refreshers returns a map of [service.Refresher], the keys of which are the
// names of their identifiers.
func (r *Registry) Refreshers() (refrs map[string]service.Refresher) {
	if r == nil {
		return nil
	}

	return r.refrs
}

// Services returns a map of [service.Interface], the keys of which are the
// names of their identifiers.
func (r *Registry) Services() (svcs map[string]service.Interface) {
	if r == nil {
		return nil
	}

	return r.svcs
}
