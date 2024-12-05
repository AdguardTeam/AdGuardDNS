package metrics

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// MainMiddleware is an interface for collection of the statistics of the main
// filtering middleware.
//
// NOTE:  Keep in sync with [dnssvc.MainMiddleware].
type MainMiddleware interface {
	OnRequest(ctx context.Context, m *MainMiddlewareRequestMetrics)
}

// MainMiddlewareRequestMetrics is an alias for a structure that contains the
// information about a request that has reached the filtering middleware.
//
// See [mainmw.RequestMetrics].
type MainMiddlewareRequestMetrics = struct {
	RemoteIP          netip.Addr
	Continent         string
	Country           string
	FilterListID      string
	FilteringDuration time.Duration
	ASN               uint32
	IsAnonymous       bool
	IsBlocked         bool
}

// DefaultMainMiddleware is the Prometheus-based implementation of the
// [MainMiddleware] interface.
type DefaultMainMiddleware struct {
	// filteringDuration is a histogram with the durations of actually filtering
	// (e.g. applying filters, safebrowsing, etc) to queries.
	filteringDuration prometheus.Histogram

	// requestPerASNTotal is a counter with the total number of queries
	// processed labeled by country and AS number.
	requestPerASNTotal *prometheus.CounterVec

	// requestPerCountryTotal is a counter with the total number of queries
	// processed labeled by country, continent, and whether any filter has been
	// applied.
	requestPerCountryTotal *prometheus.CounterVec

	// requestPerFilterTotal is a counter with the total number of queries
	// processed labeled by a filter.  Processed could mean that the request was
	// blocked or unblocked by a rule from that filter list.  "filter" contains
	// the ID of the filter list applied.  "anonymous" is "0" if the request is
	// from a AdGuard DNS customer, otherwise it is "1".
	requestPerFilterTotal *prometheus.CounterVec

	// userCounter is the main user statistics counter.
	userCounter *UserCounter
}

// NewDefaultMainMiddleware registers the filtering-middleware metrics in reg
// and returns a properly initialized *DefaultMainMiddleware.
func NewDefaultMainMiddleware(
	namespace string,
	reg prometheus.Registerer,
) (m *DefaultMainMiddleware, err error) {
	const (
		filteringDuration      = "filtering_duration_seconds"
		requestPerASNTotal     = "request_per_asn_total"
		requestPerCountryTotal = "request_per_country_total"
		requestPerFilterTotal  = "request_per_filter_total"
		usersLastDayCount      = "users_last_day_count"
		usersLastHourCount     = "users_last_hour_count"
	)

	m = &DefaultMainMiddleware{
		filteringDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      "filtering_duration_seconds",
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help:      "Time elapsed on processing a DNS query.",
			// Filtering should be quite fast (microseconds) so the buckets were
			// chosen accordingly.
			Buckets: []float64{
				// Starting from 1 microsecond
				0.000001,
				// 10 microseconds
				0.00001,
				// 50 microseconds
				0.00005,
				// 100 microseconds
				0.0001,
				// 1 millisecond
				0.001,
				// 10 milliseconds: if we got there, something went really
				// wrong.
				0.01,
				0.1,
				1,
			},
		}),

		requestPerASNTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      requestPerASNTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help:      "The number of processed DNS requests labeled by country and ASN.",
			ConstLabels: prometheus.Labels{
				dontStoreLabel: dontStoreLabelValue,
			},
		}, []string{"country", "asn"}),

		requestPerCountryTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      requestPerCountryTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help: "The number of processed DNS requests labeled by country and continent. " +
				"filters_applied=0 means that no filter has been applied",
		}, []string{"continent", "country", "filters_applied"}),

		requestPerFilterTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      requestPerFilterTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help:      "The number of filtered DNS requests labeled by filter applied.",
		}, []string{"filter", "anonymous"}),
	}

	ipsLastDay := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:      usersLastDayCount,
		Namespace: namespace,
		Subsystem: subsystemDNSSvc,
		Help:      "The approximate number of DNS users for the last 24 hours.",
	})

	ipsLastHour := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:      usersLastHourCount,
		Namespace: namespace,
		Subsystem: subsystemDNSSvc,
		Help:      "The approximate number of DNS users for the last 1 hour.",
	})

	m.userCounter = NewUserCounter(ipsLastHour, ipsLastDay)

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   filteringDuration,
		Value: m.filteringDuration,
	}, {
		Key:   requestPerASNTotal,
		Value: m.requestPerASNTotal,
	}, {
		Key:   requestPerCountryTotal,
		Value: m.requestPerCountryTotal,
	}, {
		Key:   requestPerFilterTotal,
		Value: m.requestPerFilterTotal,
	}, {
		Key:   usersLastDayCount,
		Value: ipsLastDay,
	}, {
		Key:   usersLastHourCount,
		Value: ipsLastHour,
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

// OnRequest implements the [Metrics] interface for *DefaultMainMiddleware.
func (m *DefaultMainMiddleware) OnRequest(_ context.Context, rm *MainMiddlewareRequestMetrics) {
	m.filteringDuration.Observe(rm.FilteringDuration.Seconds())

	asnStr := strconv.FormatUint(uint64(rm.ASN), 10)
	m.requestPerASNTotal.WithLabelValues(rm.Country, asnStr).Inc()

	// FilterListID is only empty if no filter has been applied.
	filtersApplied := BoolString(rm.FilterListID != "")
	m.requestPerCountryTotal.WithLabelValues(rm.Continent, rm.Country, filtersApplied).Inc()

	m.requestPerFilterTotal.WithLabelValues(rm.FilterListID, BoolString(rm.IsAnonymous)).Inc()

	// Assume that ip is the remote IP address, which has already been unmapped
	// by [netutil.NetAddrToAddrPort].
	ipArr := rm.RemoteIP.As16()
	m.userCounter.Record(time.Now(), ipArr[:], false)
}
