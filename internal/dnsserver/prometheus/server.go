package prometheus

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ServerMetricsListener implements the [dnsserver.MetricsListener] interface
// and increments prom counters.
type ServerMetricsListener struct{}

// type check
var _ dnsserver.MetricsListener = (*ServerMetricsListener)(nil)

// OnRequest implements the [dnsserver.MetricsListener] interface for
// [*ServerMetricsListener].
func (l *ServerMetricsListener) OnRequest(
	ctx context.Context,
	req, resp *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	startTime := dnsserver.MustStartTimeFromContext(ctx)

	// Increment total requests
	reqLabels := requestLabels(ctx, req, rw)
	requestTotal.With(reqLabels).Inc()

	// Increment request duration
	srvLabels := baseLabels(ctx)
	elapsed := time.Since(startTime).Seconds()
	requestDuration.With(srvLabels).Observe(elapsed)

	// Increment request size.
	ri := dnsserver.MustRequestInfoFromContext(ctx)
	requestSize.With(srvLabels).Observe(float64(ri.RequestSize))

	// If resp is not nil, increment response-related metrics
	if resp != nil {
		responseSize.With(srvLabels).Observe(float64(ri.ResponseSize))

		resLabels := baseLabels(ctx)
		resLabels["rcode"] = rCodeToString(resp.Rcode)
		responseRCode.With(resLabels).Inc()
	} else {
		// If resp is nil, increment responseRCode with a special "rcode"
		// label value ("DROPPED").
		resLabels := baseLabels(ctx)
		resLabels["rcode"] = "DROPPED"
		responseRCode.With(resLabels).Inc()
	}
}

// OnInvalidMsg implements the [dnsserver.MetricsListener] interface for
// [*ServerMetricsListener].
func (l *ServerMetricsListener) OnInvalidMsg(ctx context.Context) {
	labels := baseLabels(ctx)
	invalidMsgTotal.With(labels).Inc()
}

// OnError implements the [dnsserver.MetricsListener] interface for
// [*ServerMetricsListener].
func (l *ServerMetricsListener) OnError(ctx context.Context, _ error) {
	labels := baseLabels(ctx)
	errorTotal.With(labels).Inc()
}

// OnPanic implements the [dnsserver.MetricsListener] interface for
// [*ServerMetricsListener].
func (l *ServerMetricsListener) OnPanic(ctx context.Context, _ any) {
	labels := baseLabels(ctx)
	panicTotal.With(labels).Inc()
}

// OnQUICAddressValidation implements the [dnsserver.MetricsListener] interface
// for [*ServerMetricsListener].
func (l *ServerMetricsListener) OnQUICAddressValidation(hit bool) {
	if hit {
		quicAddrValidationCacheLookupsHits.Inc()
	} else {
		quicAddrValidationCacheLookupsMisses.Inc()
	}
}

// This block contains prometheus metrics declarations for [dnsserver.Server]
var (
	requestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "request_total",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help:      "The number of processed DNS requests.",
	}, []string{"name", "proto", "network", "addr", "type", "family"})

	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "request_duration_seconds",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help:      "Time elapsed on processing a DNS query.",
	}, []string{"name", "proto", "addr"})

	requestSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "request_size_bytes",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help:      "Time elapsed on processing a DNS query.",
		Buckets: []float64{
			0, 50, 100, 200, 300, 511, 1023, 4095, 8291,
		},
	}, []string{"name", "proto", "addr"})

	responseSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "response_size_bytes",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help:      "Time elapsed on processing a DNS query.",
		Buckets: []float64{
			0, 50, 100, 200, 300, 511, 1023, 4095, 8291,
		},
	}, []string{"name", "proto", "addr"})

	responseRCode = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "response_rcode_total",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help:      "The counter for DNS response codes.",
	}, []string{"name", "proto", "addr", "rcode"})

	errorTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "error_total",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help:      "The number of errors occurred in the DNS server.",
	}, []string{"name", "proto", "addr"})

	panicTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "panic_total",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help:      "The number of panics occurred in the DNS server.",
	}, []string{"name", "proto", "addr"})

	invalidMsgTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "invalid_msg_total",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help:      "The number of invalid DNS messages processed by the DNS server.",
	}, []string{"name", "proto", "addr"})
)

var (
	quicAddrValidationCacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "quic_addr_validation_lookups",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help: "The number of QUIC address validation lookups." +
			"hit=1 means that a cached item was found.",
	}, []string{"hit"})

	quicAddrValidationCacheLookupsHits   = quicAddrValidationCacheLookups.WithLabelValues("1")
	quicAddrValidationCacheLookupsMisses = quicAddrValidationCacheLookups.WithLabelValues("0")
)
