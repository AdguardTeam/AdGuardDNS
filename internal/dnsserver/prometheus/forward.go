package prometheus

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// ForwardMetricsListener implements the [forward.MetricsListener] interface
// and increments prom counters.
type ForwardMetricsListener struct {
	requestsTotal   *prometheus.CounterVec
	responseRCode   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	errorsTotal     *prometheus.CounterVec
	upstreamStatus  *prometheus.GaugeVec

	// mu protects statusGauges.
	mu *sync.Mutex

	// statusGauges stores the gauges corresponding to the upstream to avoid
	// allocating the labels each time the upstream status changes.
	statusGauges map[forward.Upstream]prometheus.Gauge
}

// NewForwardMetricsListener returns a properly initialized
// *ForwardMetricsListener expecting to track upsNumHint upstreams.  As long as
// this function registers prometheus counters it must be called only once.
func NewForwardMetricsListener(
	namespace string,
	reg prometheus.Registerer,
	upsNumHint int,
) (f *ForwardMetricsListener, err error) {
	const (
		requestsTotal   = "request_total"
		responseRCode   = "response_rcode_total"
		requestDuration = "request_duration_seconds"
		errorsTotal     = "error_total"
		upstreamStatus  = "upstream_status"
	)

	f = &ForwardMetricsListener{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      requestsTotal,
			Namespace: namespace,
			Subsystem: subsystemForward,
			Help:      "The number of processed DNS requests.",
		}, []string{"to", "network"}),

		responseRCode: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      responseRCode,
			Namespace: namespace,
			Subsystem: subsystemForward,
			Help:      "The counter for DNS response codes.",
		}, []string{"to", "rcode"}),

		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:      requestDuration,
			Namespace: namespace,
			Subsystem: subsystemForward,
			Help:      "Time elapsed on processing a DNS query.",
		}, []string{"to"}),

		errorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      errorsTotal,
			Namespace: namespace,
			Subsystem: subsystemForward,
			Help:      "The number of errors occurred when processing a DNS query.",
		}, []string{"to", "type"}),

		upstreamStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      upstreamStatus,
			Namespace: namespace,
			Subsystem: subsystemForward,
			Help:      "Status of the main upstream. 1 is okay, 0 the upstream is backed off",
		}, []string{"to", "type"}),

		mu: &sync.Mutex{},

		statusGauges: make(map[forward.Upstream]prometheus.Gauge, upsNumHint),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   requestsTotal,
		Value: f.requestsTotal,
	}, {
		Key:   responseRCode,
		Value: f.responseRCode,
	}, {
		Key:   requestDuration,
		Value: f.requestDuration,
	}, {
		Key:   errorsTotal,
		Value: f.errorsTotal,
	}, {
		Key:   upstreamStatus,
		Value: f.upstreamStatus,
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

	return f, nil
}

// type check
var _ forward.MetricsListener = (*ForwardMetricsListener)(nil)

// OnForwardRequest implements the [forward.MetricsListener] interface for
// *ForwardMetricsListener.
func (f *ForwardMetricsListener) OnForwardRequest(
	_ context.Context,
	ups forward.Upstream,
	_, resp *dns.Msg,
	nw forward.Network,
	startTime time.Time,
	err error,
) {
	to := ups.String()

	f.requestsTotal.WithLabelValues(to, string(nw)).Inc()
	elapsed := time.Since(startTime).Seconds()
	f.requestDuration.WithLabelValues(to).Observe(elapsed)

	if resp != nil {
		f.responseRCode.WithLabelValues(to, rCodeToString(resp.Rcode)).Inc()
	}

	if err != nil {
		f.errorsTotal.WithLabelValues(to, errorType(err)).Inc()
	}
}

// statusLabelsByUpstream returns the labels corresponding to the ups to report
// its status metrics.  It's safe for concurrent use.
func (f *ForwardMetricsListener) statusGaugeByUpstream(
	ups forward.Upstream,
	isMain bool,
) (g prometheus.Gauge) {
	f.mu.Lock()
	defer f.mu.Unlock()

	gauge, ok := f.statusGauges[ups]
	if !ok {
		labels := prometheus.Labels{
			"to":   ups.String(),
			"type": "upstream",
		}
		if !isMain {
			labels["type"] = "fallback"
		}

		gauge = f.upstreamStatus.With(labels)
		f.statusGauges[ups] = gauge
	}

	return gauge
}

// OnUpstreamStatusChanged implements the [forward.MetricsListener] interface
// for *ForwardMetricsListener.
func (f *ForwardMetricsListener) OnUpstreamStatusChanged(ups forward.Upstream, isMain, isUp bool) {
	gauge := f.statusGaugeByUpstream(ups, isMain)

	setBoolGauge(gauge, isUp)
}

// errorType returns the human-readable type of error for the metrics.
func errorType(err error) (typ string) {
	var netErr net.Error

	isNet := errors.As(err, &netErr)
	if errors.Is(err, context.DeadlineExceeded) || (isNet && netErr.Timeout()) {
		return "timeout"
	}

	if isNet {
		return "network"
	}

	return "other"
}
