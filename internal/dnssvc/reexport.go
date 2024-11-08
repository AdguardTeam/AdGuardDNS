package dnssvc

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/mainmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/ratelimitmw"
)

type (
	// MainMiddlewareMetrics is a re-export of the internal filtering-middleware
	// metrics interface.
	MainMiddlewareMetrics = mainmw.Metrics

	// RatelimitMiddlewareMetrics is a re-export of the metrics interface of the
	// internal access and ratelimiting middleware.
	RatelimitMiddlewareMetrics = ratelimitmw.Metrics
)
