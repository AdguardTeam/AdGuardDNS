package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/redisutil"
	"github.com/gomodule/redigo/redis"
	"github.com/prometheus/client_golang/prometheus"
)

// RedisKV is the Prometheus-based implementation of the [redisutil.PoolMetrics]
// interface.
type RedisKV struct {
	// activeConnections is a gauge with the total number of active connections
	// in Redis pool.  The count includes idle connections and connections in
	// use.
	activeConnections prometheus.Gauge

	// errors is a counter of errors occurred with Redis KV.
	errors prometheus.Counter
}

// NewRedisKV registers the Redis KV metrics in reg and returns a properly
// initialized [*RedisKV].
func NewRedisKV(namespace string, reg prometheus.Registerer) (m *RedisKV, err error) {
	const (
		redisActiveConnections = "redis_active_connections"
		redisErrors            = "redis_errors_total"
	)

	m = &RedisKV{
		activeConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      redisActiveConnections,
			Subsystem: subsystemDNSCheck,
			Namespace: namespace,
			Help:      "Total number of active connections in redis pool",
		}),
		errors: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      redisErrors,
			Subsystem: subsystemDNSCheck,
			Namespace: namespace,
			Help:      "Total number of errors encountered with redis pool",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   redisActiveConnections,
		Value: m.activeConnections,
	}, {
		Key:   redisErrors,
		Value: m.errors,
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

// type check
var _ redisutil.PoolMetrics = (*RedisKV)(nil)

// Update implements the [redisutil.PoolMetrics] interface for *RedisKV.
func (m *RedisKV) Update(_ context.Context, s redis.PoolStats, err error) {
	m.activeConnections.Set(float64(s.ActiveCount))

	if err != nil {
		m.errors.Inc()
	}
}

// RemoteKVOp is the type alias for string that contains remote key-value
// storage operation name.
//
// See [backendpb.RemoteKVMetrics.ObserveOperation].
type RemoteKVOp = string

// Remote key-value storage operation names for [RemoteKVOp].
//
// NOTE:  Keep in sync with [backendpb.RemoteKVOp].
const (
	RemoteKVOpGet RemoteKVOp = "get"
	RemoteKVOpSet RemoteKVOp = "set"
)

// BackendRemoteKV is the Prometheus-based implementation of the
// [backendpb.Metrics] interface.
type BackendRemoteKV struct {
	// getDuration is a histogram with the duration of a receive of a single
	// value during a call to backend remote key-value storage.
	getDuration prometheus.Observer

	// setDuration is a histogram with the duration of a sending of a single
	// value during a call to backend remote key-value storage.
	setDuration prometheus.Observer

	// hits is a counter of the total number of lookups to the remote key-value
	// storage that succeeded.
	hits prometheus.Counter

	// misses is a counter of the total number of lookups to the remote
	// key-value storage that resulted in a miss.
	misses prometheus.Counter
}

// NewBackendRemoteKV registers the backend remote key-value storage metrics in
// reg and returns a properly initialized [BackendRemoteKV].
func NewBackendRemoteKV(
	namespace string,
	reg prometheus.Registerer,
) (m *BackendRemoteKV, err error) {
	const (
		backendOpDuration = "grpc_remotekv_op_duration_seconds"
		backendLookups    = "grpc_remotekv_lookups_total"
	)

	opDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:      backendOpDuration,
		Subsystem: subsystemBackend,
		Namespace: namespace,
		Help: "Duration of a single remote key-value storage operation. " +
			"Label op is the corresponding operation name.",
		Buckets: []float64{0.000_001, 0.000_010, 0.000_100, 0.001, 0.010, 0.100},
	}, []string{"op"})

	lookups := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      backendLookups,
		Subsystem: subsystemBackend,
		Namespace: namespace,
		Help: "Total number of lookups to the remote key-value storage. " +
			"Label hit is the lookup result, either 1 for hit or 0 for miss.",
	}, []string{"hit"})

	m = &BackendRemoteKV{
		getDuration: opDuration.WithLabelValues(RemoteKVOpGet),
		setDuration: opDuration.WithLabelValues(RemoteKVOpSet),
		hits:        lookups.WithLabelValues("1"),
		misses:      lookups.WithLabelValues("0"),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   backendOpDuration,
		Value: opDuration,
	}, {
		Key:   backendLookups,
		Value: lookups,
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

// ObserveOperation implements the [backendpb.RemoteKVMetrics] interface for
// *BackendRemoteKV.
func (m *BackendRemoteKV) ObserveOperation(_ context.Context, op string, dur time.Duration) {
	switch op {
	case RemoteKVOpGet:
		m.getDuration.Observe(dur.Seconds())
	case RemoteKVOpSet:
		m.setDuration.Observe(dur.Seconds())
	default:
		panic(fmt.Errorf("operation: %w: %q", errors.ErrBadEnumValue, op))
	}
}

// IncrementLookups implements the [backendpb.RemoteKVMetrics] interface for
// *BackendRemoteKV.
func (m *BackendRemoteKV) IncrementLookups(_ context.Context, hit bool) {
	IncrementCond(hit, m.hits, m.misses)
}
