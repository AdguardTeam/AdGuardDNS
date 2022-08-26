package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// GeoIPUpdateTime is a gauge with the timestamp of the last GeoIP database
	// update.
	GeoIPUpdateTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "update_time",
		Subsystem: subsystemGeoIP,
		Namespace: namespace,
		Help:      "The time when the GeoIP was loaded last time.",
	}, []string{"path"})

	// GeoIPUpdateStatus is a gauge with the last GeoIP database update status.
	// 1 means success, 0 means an error occurred.
	GeoIPUpdateStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "update_status",
		Subsystem: subsystemGeoIP,
		Namespace: namespace,
		Help:      "Status of the last GeoIP update. 1 is okay, 0 means that something went wrong.",
	}, []string{"path"})
)

var (
	// geoIPCacheLookups is a counter with the total number of the GeoIP IP
	// cache lookups.  "hit" is either "1" (item found) or "0" (item not found).
	geoIPCacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "cache_lookups",
		Subsystem: subsystemGeoIP,
		Namespace: namespace,
		Help: "The number of GeoIP IP cache lookups. " +
			"hit=1 means that a cached item was found.",
	}, []string{"hit"})

	// GeoIPCacheLookupsHits is a counter with the total number of the GeoIP IP
	// cache hits.
	GeoIPCacheLookupsHits = geoIPCacheLookups.With(prometheus.Labels{"hit": "1"})

	// GeoIPCacheLookupsMisses is a counter with the total number of the GeoIP
	// IP cache misses.
	GeoIPCacheLookupsMisses = geoIPCacheLookups.With(prometheus.Labels{"hit": "0"})
)

var (
	// geoIPHostCacheLookups is a counter with the total number of the GeoIP
	// hostname cache lookups.  "hit" is either "1" (item found) or "0" (item
	// not found).
	geoIPHostCacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "host_cache_lookups",
		Subsystem: subsystemGeoIP,
		Namespace: namespace,
		Help: "The number of GeoIP hostname cache lookups. " +
			"hit=1 means that a cached item was found.",
	}, []string{"hit"})

	// GeoIPHostCacheLookupsHits is a counter with the total number of the GeoIP
	// hostname cache hits.
	GeoIPHostCacheLookupsHits = geoIPHostCacheLookups.With(prometheus.Labels{"hit": "1"})

	// GeoIPHostCacheLookupsMisses is a counter with the total number of the
	// GeoIP hostname cache misses.
	GeoIPHostCacheLookupsMisses = geoIPHostCacheLookups.With(prometheus.Labels{"hit": "0"})
)
