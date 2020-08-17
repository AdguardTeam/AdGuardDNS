package ratelimit

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	RateLimitedCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "ratelimit",
		Name:      "dropped_count",
		Help:      "Count of requests that have been dropped because of rate limit",
	}, []string{"server"})

	BackOffCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "ratelimit",
		Name:      "dropped_backoff_count",
		Help:      "Count of requests that have been dropped because of the backoff period",
	}, []string{"server"})

	WhitelistedCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "ratelimit",
		Name:      "whitelisted_count",
		Help:      "Count of requests that have been whitelisted in the rate limiter",
	}, []string{"server"})

	WhitelistCountGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "ratelimit",
		Name:      "whitelist_size",
		Help:      "Size of the whitelist",
	})

	RateLimitersCountGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "ratelimit",
		Name:      "ratelimiters_total",
		Help:      "Count of the currently active rate limiters",
	})

	RateLimitedIPAddressesCountGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "ratelimit",
		Name:      "ratelimited_addresses_total",
		Help:      "Count of the addresses which are currently rate limited",
	})
)
