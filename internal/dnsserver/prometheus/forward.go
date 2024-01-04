package prometheus

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ForwardMetricsListener implements the forward.MetricsListener interface
// and increments prom counters.
type ForwardMetricsListener struct {
	// mu protects statusGauges.
	mu *sync.Mutex

	// statusGauges stores the gauges corresponding to the upstream to avoid
	// allocating the labels each time the upstream status changes.
	statusGauges map[forward.Upstream]prometheus.Gauge
}

// NewForwardMetricsListener returns a properly initialized
// *ForwardMetricsListener expecting to track upsNumHint upstreams.
func NewForwardMetricsListener(upsNumHint int) (f *ForwardMetricsListener) {
	return &ForwardMetricsListener{
		mu:           &sync.Mutex{},
		statusGauges: make(map[forward.Upstream]prometheus.Gauge, upsNumHint),
	}
}

// type check
var _ forward.MetricsListener = (*ForwardMetricsListener)(nil)

// OnForwardRequest implements the forward.MetricsListener interface for
// *ForwardMetricsListener.
func (f *ForwardMetricsListener) OnForwardRequest(
	_ context.Context,
	ups forward.Upstream,
	_, resp *dns.Msg,
	nw forward.Network,
	startTime time.Time,
	err error,
) {
	// Here and below stick to using WithLabelValues instead of With in order
	// to avoid extra allocations on prometheus.Labels.

	to := ups.String()

	forwardRequestTotal.WithLabelValues(to, string(nw)).Inc()
	elapsed := time.Since(startTime).Seconds()
	forwardRequestDuration.WithLabelValues(to).Observe(elapsed)

	if resp != nil {
		forwardResponseRCode.WithLabelValues(to, rCodeToString(resp.Rcode)).Inc()
	}

	if err != nil {
		forwardErrorTotal.WithLabelValues(to, errorType(err)).Inc()
	}
}

// statusLabelsByUpstream returns the labels corresponding to the ups to report
// it's status metrics.  It's safe for concurrent use.
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

		gauge = forwardUpstreamStatus.With(labels)
		f.statusGauges[ups] = gauge
	}

	return gauge
}

// OnUpstreamStatusChanged implements the forward.MetricsListener interface for
// *ForwardMetricsListener.
func (f *ForwardMetricsListener) OnUpstreamStatusChanged(
	ups forward.Upstream,
	isMain bool,
	status bool,
) {
	gauge := f.statusGaugeByUpstream(ups, isMain)

	setBoolGauge(gauge, status)
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

// This block contains prometheus metrics declarations for forward.Handler.
var (
	forwardRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "request_total",
		Namespace: namespace,
		Subsystem: subsystemForward,
		Help:      "The number of processed DNS requests.",
	}, []string{"to", "network"})

	forwardResponseRCode = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "response_rcode_total",
		Namespace: namespace,
		Subsystem: subsystemForward,
		Help:      "The counter for DNS response codes.",
	}, []string{"to", "rcode"})

	forwardRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "request_duration_seconds",
		Namespace: namespace,
		Subsystem: subsystemForward,
		Help:      "Time elapsed on processing a DNS query.",
	}, []string{"to"})

	forwardErrorTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "error_total",
		Namespace: namespace,
		Subsystem: subsystemForward,
		Help:      "The number of errors occurred when processing a DNS query.",
	}, []string{"to", "type"})

	forwardUpstreamStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "upstream_status",
		Namespace: namespace,
		Subsystem: subsystemForward,
		Help:      "Status of the main upstream. 1 is okay, 0 the upstream is backed off",
	}, []string{"to", "type"})
)
