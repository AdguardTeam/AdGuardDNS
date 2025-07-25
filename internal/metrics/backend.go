package metrics

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// GRPCError is a type alias for string that contains gGRPC error type.
//
// See [backendpb.GRPCMetrics.IncrementErrorCount].
type GRPCError = string

// gRPC errors of [GRPCError] type.
//
// NOTE:  Keep in sync with [backendpb.GRPCError].
const (
	GRPCErrAuthentication GRPCError = "auth"
	GRPCErrBadRequest     GRPCError = "bad_req"
	GRPCErrDeviceQuota    GRPCError = "dev_quota"
	GRPCErrNotFound       GRPCError = "not_found"
	GRPCErrOther          GRPCError = "other"
	GRPCErrRateLimit      GRPCError = "rate_limit"
	GRPCErrTimeout        GRPCError = "timeout"
)

// BackendGRPC is the Prometheus-based implementation of the
// [backendpb.GRPCMetrics] interface.
type BackendGRPC struct {
	errorsTotalAuthentication prometheus.Counter
	errorsTotalBadRequest     prometheus.Counter
	errorsTotalDeviceQuota    prometheus.Counter
	errorsTotalNotFound       prometheus.Counter
	errorsTotalOther          prometheus.Counter
	errorsTotalRateLimit      prometheus.Counter
	errorsTotalTimeout        prometheus.Counter
}

// NewBackendGRPC registers the protobuf errors metrics in reg and returns a
// properly initialized [BackendGRPC].
func NewBackendGRPC(namespace string, reg prometheus.Registerer) (m *BackendGRPC, err error) {
	const grpcErrorsTotal = "grpc_errors_total"

	// grpcErrorsTotalCounterVec is a vector of counters of gRPC errors by type.
	grpcErrorsTotalCounterVec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      grpcErrorsTotal,
		Subsystem: subsystemBackend,
		Namespace: namespace,
		Help:      "The total number of errors by type.",
	}, []string{"type"})

	m = &BackendGRPC{
		errorsTotalAuthentication: grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrAuthentication),
		errorsTotalBadRequest:     grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrBadRequest),
		errorsTotalDeviceQuota:    grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrDeviceQuota),
		errorsTotalNotFound:       grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrNotFound),
		errorsTotalOther:          grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrOther),
		errorsTotalRateLimit:      grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrRateLimit),
		errorsTotalTimeout:        grpcErrorsTotalCounterVec.WithLabelValues(GRPCErrTimeout),
	}

	err = reg.Register(grpcErrorsTotalCounterVec)
	if err != nil {
		return nil, fmt.Errorf("registering metrics %q: %w", grpcErrorsTotal, err)
	}

	return m, nil
}

// IncrementErrorCount implements the [backendpb.GRPCMetrics] interface for
// BackendGRPC.
func (m *BackendGRPC) IncrementErrorCount(_ context.Context, errType GRPCError) {
	var ctr prometheus.Counter
	switch errType {
	case GRPCErrAuthentication:
		ctr = m.errorsTotalAuthentication
	case GRPCErrBadRequest:
		ctr = m.errorsTotalBadRequest
	case GRPCErrDeviceQuota:
		ctr = m.errorsTotalDeviceQuota
	case GRPCErrNotFound:
		ctr = m.errorsTotalNotFound
	case GRPCErrOther:
		ctr = m.errorsTotalOther
	case GRPCErrRateLimit:
		ctr = m.errorsTotalRateLimit
	case GRPCErrTimeout:
		ctr = m.errorsTotalTimeout
	default:
		panic(fmt.Errorf("BackendGRPC.IncrementErrorCount: bad type %q", errType))
	}

	ctr.Inc()
}
