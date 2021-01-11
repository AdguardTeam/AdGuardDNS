package lrucache

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func newDNSCounter(name string, help string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "lrucache",
		Name:      name,
		Help:      help,
	})
}

var (
	lruCacheHits   = newDNSCounter("lrucache_hits_total", "Count of LRU cache hits")
	lruCacheMisses = newDNSCounter("lrucache_misses_total", "Count of LRU cache misses")
)
