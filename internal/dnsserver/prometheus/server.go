package prometheus

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/prometheus/client_golang/prometheus"
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
func NewServerMetricsListener(
	namespace string,
	reg prometheus.Registerer,
) (l *ServerMetricsListener, err error) {
	const (
		reqTotalMtrcName        = "request_total"
		reqDurationMtrcName     = "request_duration_seconds"
		reqSizeMtrcName         = "request_size_bytes"
		respSizeMtrcName        = "response_size_bytes"
		respRCodeMtrcName       = "response_rcode_total"
		errTotalMtrcName        = "error_total"
		panicTotalMtrcName      = "panic_total"
		invalidMsgTotalMtrcName = "invalid_msg_total"
		quicAddrLookupsMtrcName = "quic_addr_validation_lookups"
	)

	var (
		requestTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      reqTotalMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help:      "The number of processed DNS requests.",
		}, []string{"name", "proto", "network", "addr", "type", "family"})

		requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:      reqDurationMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help:      "Time elapsed on processing a DNS query.",
		}, []string{"name", "proto", "addr"})

		requestSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:      reqSizeMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help:      "Time elapsed on processing a DNS query.",
			Buckets: []float64{
				0, 50, 100, 200, 300, 511, 1023, 4095, 8291,
			},
		}, []string{"name", "proto", "addr"})

		responseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:      respSizeMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help:      "Time elapsed on processing a DNS query.",
			Buckets: []float64{
				0, 50, 100, 200, 300, 511, 1023, 4095, 8291,
			},
		}, []string{"name", "proto", "addr"})

		responseRCode = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      respRCodeMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help:      "The counter for DNS response codes.",
		}, []string{"name", "proto", "addr", "rcode"})

		errorTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      errTotalMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help:      "The number of errors occurred in the DNS server.",
		}, []string{"name", "proto", "addr"})

		panicTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      panicTotalMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help:      "The number of panics occurred in the DNS server.",
		}, []string{"name", "proto", "addr"})

		invalidMsgTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      invalidMsgTotalMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help:      "The number of invalid DNS messages processed by the DNS server.",
		}, []string{"name", "proto", "addr"})

		quicAddrValidationCacheLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      quicAddrLookupsMtrcName,
			Namespace: namespace,
			Subsystem: subsystemServer,
			Help: "The number of QUIC address validation lookups." +
				"hit=1 means that a cached item was found.",
		}, []string{"hit"})
	)

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   reqTotalMtrcName,
		Value: requestTotal,
	}, {
		Key:   reqDurationMtrcName,
		Value: requestDuration,
	}, {
		Key:   reqSizeMtrcName,
		Value: requestSize,
	}, {
		Key:   respSizeMtrcName,
		Value: responseSize,
	}, {
		Key:   respRCodeMtrcName,
		Value: responseRCode,
	}, {
		Key:   errTotalMtrcName,
		Value: errorTotal,
	}, {
		Key:   panicTotalMtrcName,
		Value: panicTotal,
	}, {
		Key:   invalidMsgTotalMtrcName,
		Value: invalidMsgTotal,
	}, {
		Key:   quicAddrLookupsMtrcName,
		Value: quicAddrValidationCacheLookups,
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
	}, nil
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
