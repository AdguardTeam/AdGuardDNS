package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// GeoIP is the Prometheus-based implementation of the [geoip.Metrics]
// interface.
type GeoIP struct {
	updateASNTimestamp prometheus.Gauge
	updateASNStatus    prometheus.Gauge

	updateCountryTimestamp prometheus.Gauge
	updateCountryStatus    prometheus.Gauge

	hostHits   prometheus.Counter
	hostMisses prometheus.Counter

	ipHits   prometheus.Counter
	ipMisses prometheus.Counter
}

// NewGeoIP registers the GeoIP metrics in reg and returns a properly
// initialized GeoIP.
func NewGeoIP(
	namespace string,
	reg prometheus.Registerer,
	asnPath string,
	ctryPath string,
) (m *GeoIP, err error) {
	const (
		updateStatus     = "update_status"
		updateTime       = "update_time"
		ipCacheLookups   = "cache_lookups"
		hostCacheLookups = "host_cache_lookups"
	)

	ipCacheLookupsCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      ipCacheLookups,
		Subsystem: subsystemGeoIP,
		Namespace: namespace,
		Help: "The number of GeoIP IP cache lookups. " +
			"hit=1 means that a cached item was found.",
	}, []string{"hit"})
	hostCacheLookupsCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      hostCacheLookups,
		Subsystem: subsystemGeoIP,
		Namespace: namespace,
		Help: "The number of GeoIP hostname cache lookups. " +
			"hit=1 means that a cached item was found.",
	}, []string{"hit"})
	updateTimestampGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      updateTime,
		Subsystem: subsystemGeoIP,
		Namespace: namespace,
		Help:      "The time when the GeoIP was loaded last time.",
	}, []string{"path"})
	updateStatusGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      updateStatus,
		Subsystem: subsystemGeoIP,
		Namespace: namespace,
		Help: "Status of the last GeoIP update. " +
			"1 is okay, 0 means that something went wrong.",
	}, []string{"path"})

	m = &GeoIP{
		updateASNTimestamp: updateTimestampGauge.WithLabelValues(asnPath),
		updateASNStatus:    updateStatusGauge.WithLabelValues(asnPath),

		updateCountryTimestamp: updateTimestampGauge.WithLabelValues(ctryPath),
		updateCountryStatus:    updateStatusGauge.WithLabelValues(ctryPath),

		hostHits:   hostCacheLookupsCount.WithLabelValues("1"),
		hostMisses: hostCacheLookupsCount.WithLabelValues("0"),

		ipHits:   ipCacheLookupsCount.WithLabelValues("1"),
		ipMisses: ipCacheLookupsCount.WithLabelValues("0"),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   updateStatus,
		Value: updateStatusGauge,
	}, {
		Key:   updateTime,
		Value: updateTimestampGauge,
	}, {
		Key:   ipCacheLookups,
		Value: ipCacheLookupsCount,
	}, {
		Key:   hostCacheLookups,
		Value: hostCacheLookupsCount,
	}}

	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

	return m, nil
}

// HandleASNUpdateStatus implements the [geoip.Metrics] interface for *GeoIP.
func (m *GeoIP) HandleASNUpdateStatus(_ context.Context, err error) {
	if err != nil {
		m.updateASNStatus.Set(0)

		return
	}

	m.updateASNStatus.Set(1)
	m.updateASNTimestamp.SetToCurrentTime()
}

// HandleCountryUpdateStatus implements the [geoip.Metrics] interface for
// *GeoIP.
func (m *GeoIP) HandleCountryUpdateStatus(_ context.Context, err error) {
	if err != nil {
		m.updateCountryStatus.Set(0)

		return
	}

	m.updateCountryStatus.Set(1)
	m.updateCountryTimestamp.SetToCurrentTime()
}

// IncrementHostCacheLookups implements the [geoip.Metrics] interface for
// *GeoIP.
func (m *GeoIP) IncrementHostCacheLookups(_ context.Context, hit bool) {
	IncrementCond(hit, m.hostHits, m.hostMisses)
}

// IncrementIPCacheLookups implements the [geoip.Metrics] interface for *GeoIP.
func (m *GeoIP) IncrementIPCacheLookups(_ context.Context, hit bool) {
	IncrementCond(hit, m.ipHits, m.ipMisses)
}
