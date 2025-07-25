package dnssvc

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicefinder"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/mainmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/ratelimitmw"
)

// Re-exports related to configuration.
type (
	// DDRConfig is the configuration for the server group's Discovery Of
	// Designated Resolvers (DDR) handlers.
	DDRConfig = initial.DDRConfig
)

// Re-exports related to custom domains.
type (
	// CustomDomainDB contains information about custom domains and matches domains.
	CustomDomainDB = devicefinder.CustomDomainDB

	// EmptyCustomDomainDB is an [CustomDomainDB] that does nothing.
	EmptyCustomDomainDB = devicefinder.EmptyCustomDomainDB
)

// Re-exports related to metrics.
type (
	// DeviceFinderMetrics is an interface for collection of the statistics of
	// the default device finder.
	DeviceFinderMetrics = devicefinder.Metrics

	// InitialMiddlewareMetrics is an interface for monitoring the initial
	// middleware state.
	InitialMiddlewareMetrics = initial.Metrics

	// MainMiddlewareMetrics is an interface for collection of the statistics of
	// the main filtering middleware.
	MainMiddlewareMetrics = mainmw.Metrics

	// RatelimitMiddlewareMetrics is an interface for monitoring the ratelimit
	// middleware state.
	RatelimitMiddlewareMetrics = ratelimitmw.Metrics
)
