package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// RedisKV is the Prometheus-based implementation of the [rediskv.Metrics]
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
// initialized [RedisKV].
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

// UpdateMetrics implements the [rediskv.Metrics] interface for *RedisKV.
func (m *RedisKV) UpdateMetrics(_ context.Context, val uint, isSuccess bool) {
	m.activeConnections.Set(float64(val))

	if !isSuccess {
		m.errors.Inc()
	}
}
