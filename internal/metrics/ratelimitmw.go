package metrics

import (
	"context"
	"fmt"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// RatelimitMiddleware is the Prometheus-based implementation of the
// [dnssvc.RatelimitMiddleware] interface.
type RatelimitMiddleware struct {
	allowlistedTotalCounters *syncutil.OnceConstructor[reqLabelMetricKey, prometheus.Counter]
	droppedTotalCounters     *syncutil.OnceConstructor[reqLabelMetricKey, prometheus.Counter]

	accessBlockedByHostTotal    prometheus.Counter
	accessBlockedByProfileTotal prometheus.Counter
	accessBlockedBySubnetTotal  prometheus.Counter
	ratelimitedByProfile        prometheus.Counter
}

// NewRatelimitMiddleware registers the middleware metrics of the access and
// ratelimiting middleware in reg and returns a properly initialized
// *RatelimitMiddleware.
func NewRatelimitMiddleware(
	namespace string,
	reg prometheus.Registerer,
) (m *RatelimitMiddleware, err error) {
	// NOTE:  For historical reasons, this entity contains counters from
	// multiple namespaces.  Do not change them without notifying the
	// infrastructure team.

	const (
		allowlistedTotal = "allowlisted_total"
		droppedTotal     = "dropped_total"

		accessBlockedByHostTotal    = "blocked_host_total"
		accessBlockedByProfileTotal = "profile_blocked_total"
		accessBlockedBySubnetTotal  = "blocked_subnet_total"
		ratelimitedByProfile        = "profile_ratelimited_total"
	)

	allowlistedTotalCounters := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      allowlistedTotal,
		Namespace: namespace,
		Subsystem: subsystemRateLimit,
		Help:      "The total number of allowlisted DNS queries.",
	}, []string{"name", "proto", "network", "addr", "type", "family"})

	droppedTotaCounters := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      droppedTotal,
		Namespace: namespace,
		Subsystem: subsystemRateLimit,
		Help:      "The total number of rate-limited DNS queries.",
	}, []string{"name", "proto", "network", "addr", "type", "family"})

	m = &RatelimitMiddleware{
		allowlistedTotalCounters: syncutil.NewOnceConstructor(
			func(k reqLabelMetricKey) (c prometheus.Counter) {
				return k.withLabelValues(allowlistedTotalCounters)
			},
		),

		droppedTotalCounters: syncutil.NewOnceConstructor(
			func(k reqLabelMetricKey) (c prometheus.Counter) {
				return k.withLabelValues(droppedTotaCounters)
			},
		),

		accessBlockedByHostTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      accessBlockedByHostTotal,
			Namespace: namespace,
			Subsystem: subsystemAccess,
			Help:      "Total count of blocked host requests.",
		}),

		accessBlockedByProfileTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      accessBlockedByProfileTotal,
			Namespace: namespace,
			Subsystem: subsystemAccess,
			Help:      "Total count of requests blocked by a profile's access settings.",
		}),

		accessBlockedBySubnetTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      accessBlockedBySubnetTotal,
			Namespace: namespace,
			Subsystem: subsystemAccess,
			Help:      "Total count of blocked subnet requests.",
		}),

		ratelimitedByProfile: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      ratelimitedByProfile,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help:      "Total count of requests dropped by profile ratelimit.",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   allowlistedTotal,
		Value: allowlistedTotalCounters,
	}, {
		Key:   droppedTotal,
		Value: droppedTotaCounters,
	}, {
		Key:   accessBlockedByHostTotal,
		Value: m.accessBlockedByHostTotal,
	}, {
		Key:   accessBlockedByProfileTotal,
		Value: m.accessBlockedByProfileTotal,
	}, {
		Key:   accessBlockedBySubnetTotal,
		Value: m.accessBlockedBySubnetTotal,
	}, {
		Key:   ratelimitedByProfile,
		Value: m.ratelimitedByProfile,
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

// IncrementAccessBlockedByHost implements the [RatelimitMiddleware] interface
// for *RatelimitMiddleware.
func (m *RatelimitMiddleware) IncrementAccessBlockedByHost(_ context.Context) {
	m.accessBlockedByHostTotal.Inc()
}

// IncrementAccessBlockedByProfile implements the [RatelimitMiddleware]
// interface for *RatelimitMiddleware.
func (m *RatelimitMiddleware) IncrementAccessBlockedByProfile(_ context.Context) {
	m.accessBlockedByProfileTotal.Inc()
}

// IncrementAccessBlockedBySubnet implements the [RatelimitMiddleware] interface
// for *RatelimitMiddleware.
func (m *RatelimitMiddleware) IncrementAccessBlockedBySubnet(_ context.Context) {
	m.accessBlockedBySubnetTotal.Inc()
}

// IncrementRatelimitedByProfile implements the [RatelimitMiddleware] interface
// for *RatelimitMiddleware.
func (m *RatelimitMiddleware) IncrementRatelimitedByProfile(_ context.Context) {
	m.ratelimitedByProfile.Inc()
}

// OnAllowlisted implements the [RatelimitMiddleware] interface for
// *RatelimitMiddleware.
func (m *RatelimitMiddleware) OnAllowlisted(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	m.allowlistedTotalCounters.Get(newReqLabelMetricKey(ctx, req, rw)).Inc()
}

// OnRateLimited implements the [RatelimitMiddleware] interface for
// *RatelimitMiddleware.
func (m *RatelimitMiddleware) OnRateLimited(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	m.droppedTotalCounters.Get(newReqLabelMetricKey(ctx, req, rw)).Inc()
}

// reqLabelMetricKey contains the information for a request label.
type reqLabelMetricKey struct {
	network string
	qType   string
	family  string
	srvInfo dnsserver.ServerInfo
}

// newReqLabelMetricKey returns a new metric key from the given data.
//
// NOTE:  Keep in sync with package prometheus in module dnsserver.
func newReqLabelMetricKey(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) (k reqLabelMetricKey) {
	return reqLabelMetricKey{
		network: string(dnsserver.NetworkFromAddr(rw.LocalAddr())),
		qType:   typeToString(req),
		family:  raddrToFamily(rw.RemoteAddr()),
		srvInfo: *dnsserver.MustServerInfoFromContext(ctx),
	}
}

// withLabelValues returns a counter with the given arguments in the correct
// order.
//
// NOTE:  Keep in sync with package prometheus in module dnsserver.
func (k reqLabelMetricKey) withLabelValues(vec *prometheus.CounterVec) (c prometheus.Counter) {
	// The labels must be in the following order:
	//   1. server name;
	//   2. server protocol;
	//   3. server socket network ("tcp"/"udp");
	//   4. server addr;
	//   5. question type (see [typeToString]);
	//   6. IP family (see [raddrToFamily]).
	return vec.WithLabelValues(
		k.srvInfo.Name,
		k.srvInfo.Proto.String(),
		k.network,
		k.srvInfo.Addr,
		k.qType,
		k.family,
	)
}

// raddrToFamily returns a family metric value for raddr.  The values are:
//
//  0. Unknown.
//  1. IPv4.
//  2. IPv6.
//
// NOTE:  Keep in sync with package prometheus in module dnsserver.
func raddrToFamily(raddr net.Addr) (family string) {
	ip := netutil.NetAddrToAddrPort(raddr).Addr()

	if !ip.IsValid() {
		return "0"
	} else if ip.Is4() {
		return "1"
	}

	return "2"
}

// typeToString converts query type to a human-readable string.
//
// NOTE:  Keep in sync with package prometheus in module dnsserver.
func typeToString(req *dns.Msg) string {
	var qType uint16
	if len(req.Question) == 1 {
		// NOTE: req can be invalid here, so check if the question is okay.
		qType = req.Question[0].Qtype
	}

	switch qType {
	case
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeDNSKEY,
		dns.TypeDS,
		dns.TypeHTTPS,
		dns.TypeMX,
		dns.TypeNS,
		dns.TypeNSEC,
		dns.TypeNSEC3,
		dns.TypePTR,
		dns.TypeRRSIG,
		dns.TypeSOA,
		dns.TypeSRV,
		dns.TypeSVCB,
		dns.TypeTXT,
		// Meta Qtypes:
		dns.TypeANY,
		dns.TypeAXFR,
		dns.TypeIXFR:
		return dns.Type(qType).String()
	}

	// Sometimes people prefer to log something like "TYPE{qtype}".  However,
	// practice shows that this creates quite a huge cardinality.
	return "OTHER"
}
