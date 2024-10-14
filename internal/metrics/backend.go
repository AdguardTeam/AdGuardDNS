package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// GRPCError is a type alias for string that contains gGRPC error type.
//
// See [backendpb.IncrementGRPCErrorCount.
type GRPCError = string

// gRPC errors of [GRPCError] type.
const (
	GRPCErrAuthentication GRPCError = "auth"
	GRPCErrBadRequest     GRPCError = "bad_req"
	GRPCErrDeviceQuota    GRPCError = "dev_quota"
	GRPCErrOther          GRPCError = "other"
	GRPCErrRateLimit      GRPCError = "rate_limit"
	GRPCErrTimeout        GRPCError = "timeout"
)

// BackendPB is the Prometheus-based implementation of the [backendpb.Metrics]
// interface.
type BackendPB struct {
	// devicesInvalidTotal is a gauge with the number of invalid user devices
	// loaded from the backend.
	devicesInvalidTotal prometheus.Counter

	// grpcAvgProfileRecvDuration is a histogram with the average duration of a
	// receive of a single profile during a backend call.
	grpcAvgProfileRecvDuration prometheus.Histogram

	// grpcAvgProfileDecDuration is a histogram with the average duration of
	// decoding a single profile during a backend call.
	grpcAvgProfileDecDuration prometheus.Histogram

	grpcErrorsTotalAuthentication prometheus.Counter
	grpcErrorsTotalBadRequest     prometheus.Counter
	grpcErrorsTotalDeviceQuota    prometheus.Counter
	grpcErrorsTotalOther          prometheus.Counter
	grpcErrorsTotalRateLimit      prometheus.Counter
	grpcErrorsTotalTimeout        prometheus.Counter
}

// NewBackendPB registers the protobuf errors metrics in reg and returns a
// properly initialized [BackendPB].
func NewBackendPB(namespace string, reg prometheus.Registerer) (m *BackendPB, err error) {
	const (
		devicesInvalidTotal        = "devices_invalid_total"
		grpcAvgProfileRecvDuration = "grpc_avg_profile_recv_duration_seconds"
		grpcAvgProfileDecDuration  = "grpc_avg_profile_dec_duration_seconds"
		grpcErrorsTotal            = "grpc_errors_total"
	)

	// grpcErrorsTotalCounterVec is a vector of counters of gRPC errors by type.
	grpcErrorsTotalCounterVec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      grpcErrorsTotal,
		Subsystem: subsystemBackend,
		Namespace: namespace,
		Help:      "The total number of errors by type.",
	}, []string{"type"})

	m = &BackendPB{
		devicesInvalidTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      devicesInvalidTotal,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The total number of invalid user devices loaded from the backend.",
		}),
		grpcAvgProfileRecvDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      grpcAvgProfileRecvDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help: "The average duration of a receive of a profile during a call to the backend, " +
				"in seconds.",
			Buckets: []float64{0.000_001, 0.000_010, 0.000_100, 0.001},
		}),
		grpcAvgProfileDecDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      grpcAvgProfileDecDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help: "The average duration of decoding one profile during a call to the backend, " +
				"in seconds.",
			Buckets: []float64{0.000_001, 0.000_01, 0.000_1, 0.001},
		}),
		grpcErrorsTotalAuthentication: grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrAuthentication),
		grpcErrorsTotalBadRequest:     grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrBadRequest),
		grpcErrorsTotalDeviceQuota:    grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrDeviceQuota),
		grpcErrorsTotalOther:          grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrOther),
		grpcErrorsTotalRateLimit:      grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrRateLimit),
		grpcErrorsTotalTimeout:        grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrTimeout),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   devicesInvalidTotal,
		Value: m.devicesInvalidTotal,
	}, {
		Key:   grpcAvgProfileRecvDuration,
		Value: m.grpcAvgProfileRecvDuration,
	}, {
		Key:   grpcAvgProfileDecDuration,
		Value: m.grpcAvgProfileDecDuration,
	}, {
		Key:   grpcErrorsTotal,
		Value: grpcErrorsTotalCounterVec,
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

// IncrementGRPCErrorCount implements the [Metrics] interface for BackendPB.
func (m *BackendPB) IncrementGRPCErrorCount(_ context.Context, errType GRPCError) {
	var ctr prometheus.Counter
	switch errType {
	case GRPCErrAuthentication:
		ctr = m.grpcErrorsTotalAuthentication
	case GRPCErrBadRequest:
		ctr = m.grpcErrorsTotalBadRequest
	case GRPCErrDeviceQuota:
		ctr = m.grpcErrorsTotalDeviceQuota
	case GRPCErrOther:
		ctr = m.grpcErrorsTotalOther
	case GRPCErrRateLimit:
		ctr = m.grpcErrorsTotalRateLimit
	case GRPCErrTimeout:
		ctr = m.grpcErrorsTotalTimeout
	default:
		panic(fmt.Errorf("BackendPB.IncrementGRPCErrorCount: bad type %q", errType))
	}

	ctr.Inc()
}

// IncrementInvalidDevicesCount implements the [Metrics] interface for
// BackendPB.
func (m *BackendPB) IncrementInvalidDevicesCount(_ context.Context) {
	m.devicesInvalidTotal.Inc()
}

// UpdateStats implements the [Metrics] interface for BackendPB.
func (m *BackendPB) UpdateStats(_ context.Context, avgRecv, avgDec time.Duration) {
	m.grpcAvgProfileRecvDuration.Observe(avgRecv.Seconds())
	m.grpcAvgProfileDecDuration.Observe(avgDec.Seconds())
}
