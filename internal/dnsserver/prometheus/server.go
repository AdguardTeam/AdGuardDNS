package prometheus

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ServerMetricsListener implements the [dnsserver.MetricsListener] interface
// and increments prom counters.
type ServerMetricsListener struct {
	quicAddrValidationCacheLookupsHits   prometheus.Counter
	quicAddrValidationCacheLookupsMisses prometheus.Counter

	reqTotalCounters *syncutil.OnceConstructor[reqLabelMetricKey, prometheus.Counter]

	respRCodeCounters *syncutil.OnceConstructor[srvInfoRCode, prometheus.Counter]

	invalidMsgCounters *syncutil.OnceConstructor[dnsserver.ServerInfo, prometheus.Counter]
	errorCounters      *syncutil.OnceConstructor[dnsserver.ServerInfo, prometheus.Counter]
	panicCounters      *syncutil.OnceConstructor[dnsserver.ServerInfo, prometheus.Counter]

	reqDurationHistograms *syncutil.OnceConstructor[dnsserver.ServerInfo, prometheus.Observer]
	reqSizeHistograms     *syncutil.OnceConstructor[dnsserver.ServerInfo, prometheus.Observer]
	respSizeHistograms    *syncutil.OnceConstructor[dnsserver.ServerInfo, prometheus.Observer]
}

// srvInfoRCode is a struct containing the server information along with a
// response code.
type srvInfoRCode struct {
	rCode string
	dnsserver.ServerInfo
}

// withLabelValues returns a counter with the server info and rcode data in the
// correct order.
func (i srvInfoRCode) withLabelValues(vec *prometheus.CounterVec) (c prometheus.Counter) {
	// The labels must be in the following order:
	//   1. server name;
	//   2. server protocol;
	//   3. server addr;
	//   4. response code;
	return vec.WithLabelValues(
		i.Name,
		i.Proto.String(),
		i.Addr,
		i.rCode,
	)
}

// NewServerMetricsListener returns a new properly initialized
// *ServerMetricsListener.  As long as this function registers prometheus
// counters it must be called only once.
//
// TODO(a.garipov): Do not use promauto.
func NewServerMetricsListener(namespace string) (l *ServerMetricsListener) {
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

	quicAddrValidationCacheLookups := promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "quic_addr_validation_lookups",
		Namespace: namespace,
		Subsystem: subsystemServer,
		Help: "The number of QUIC address validation lookups." +
			"hit=1 means that a cached item was found.",
	}, []string{"hit"})

	return &ServerMetricsListener{
		quicAddrValidationCacheLookupsHits:   quicAddrValidationCacheLookups.WithLabelValues("1"),
		quicAddrValidationCacheLookupsMisses: quicAddrValidationCacheLookups.WithLabelValues("0"),

		reqTotalCounters: syncutil.NewOnceConstructor(
			func(k reqLabelMetricKey) (c prometheus.Counter) {
				return k.withLabelValues(requestTotal)
			},
		),

		respRCodeCounters: syncutil.NewOnceConstructor(
			func(k srvInfoRCode) (c prometheus.Counter) {
				return k.withLabelValues(responseRCode)
			},
		),

		invalidMsgCounters: syncutil.NewOnceConstructor(
			func(k dnsserver.ServerInfo) (c prometheus.Counter) {
				return withSrvInfoLabelValues(invalidMsgTotal, k)
			},
		),
		errorCounters: syncutil.NewOnceConstructor(
			func(k dnsserver.ServerInfo) (c prometheus.Counter) {
				return withSrvInfoLabelValues(errorTotal, k)
			},
		),
		panicCounters: syncutil.NewOnceConstructor(
			func(k dnsserver.ServerInfo) (c prometheus.Counter) {
				return withSrvInfoLabelValues(panicTotal, k)
			},
		),

		reqDurationHistograms: syncutil.NewOnceConstructor(
			func(k dnsserver.ServerInfo) (o prometheus.Observer) {
				return withSrvInfoLabelValues(requestDuration, k)
			},
		),
		reqSizeHistograms: syncutil.NewOnceConstructor(
			func(k dnsserver.ServerInfo) (o prometheus.Observer) {
				return withSrvInfoLabelValues(requestSize, k)
			},
		),
		respSizeHistograms: syncutil.NewOnceConstructor(
			func(k dnsserver.ServerInfo) (o prometheus.Observer) {
				return withSrvInfoLabelValues(responseSize, k)
			},
		),
	}
}

// type check
var _ dnsserver.MetricsListener = (*ServerMetricsListener)(nil)

// OnRequest implements the [dnsserver.MetricsListener] interface for
// [*ServerMetricsListener].
func (l *ServerMetricsListener) OnRequest(
	ctx context.Context,
	info *dnsserver.QueryInfo,
	rw dnsserver.ResponseWriter,
) {
	serverInfo := *dnsserver.MustServerInfoFromContext(ctx)

	// Increment total requests count metrics.
	l.reqTotalCounters.Get(newReqLabelMetricKey(ctx, info.Request, rw)).Inc()

	// Increment request size.
	ri := dnsserver.MustRequestInfoFromContext(ctx)
	l.reqSizeHistograms.Get(serverInfo).Observe(float64(info.RequestSize))

	// Increment request duration histogram.
	elapsed := time.Since(ri.StartTime).Seconds()
	l.reqDurationHistograms.Get(serverInfo).Observe(elapsed)

	// If resp is not nil, increment response-related metrics.
	if resp := info.Response; resp != nil {
		l.respSizeHistograms.Get(serverInfo).Observe(float64(info.ResponseSize))
		l.respRCodeCounters.Get(srvInfoRCode{
			ServerInfo: serverInfo,
			rCode:      rCodeToString(resp.Rcode),
		}).Inc()
	} else {
		// If resp is nil, increment responseRCode with a special "rcode" label
		// value ("DROPPED").
		l.respRCodeCounters.Get(srvInfoRCode{
			ServerInfo: serverInfo,
			rCode:      "DROPPED",
		}).Inc()
	}
}

// OnInvalidMsg implements the [dnsserver.MetricsListener] interface for
// [*ServerMetricsListener].
func (l *ServerMetricsListener) OnInvalidMsg(ctx context.Context) {
	l.invalidMsgCounters.Get(*dnsserver.MustServerInfoFromContext(ctx)).Inc()
}

// OnError implements the [dnsserver.MetricsListener] interface for
// [*ServerMetricsListener].
func (l *ServerMetricsListener) OnError(ctx context.Context, _ error) {
	l.errorCounters.Get(*dnsserver.MustServerInfoFromContext(ctx)).Inc()
}

// OnPanic implements the [dnsserver.MetricsListener] interface for
// [*ServerMetricsListener].
func (l *ServerMetricsListener) OnPanic(ctx context.Context, _ any) {
	l.panicCounters.Get(*dnsserver.MustServerInfoFromContext(ctx)).Inc()
}

// OnQUICAddressValidation implements the [dnsserver.MetricsListener] interface
// for [*ServerMetricsListener].
func (l *ServerMetricsListener) OnQUICAddressValidation(hit bool) {
	if hit {
		l.quicAddrValidationCacheLookupsHits.Inc()
	} else {
		l.quicAddrValidationCacheLookupsMisses.Inc()
	}
}
