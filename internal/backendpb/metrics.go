package backendpb

import (
	"context"
	"time"
)

// Metrics is an interface that is used for the collection of the protobuf
// errors statistics.
type Metrics interface {
	// IncrementGRPCErrorCount increments the gRPC error count of errType.
	// errType must be one of GRPCError values.
	IncrementGRPCErrorCount(ctx context.Context, errType GRPCError)

	// IncrementInvalidDevicesCount increments the number of invalid devices.
	IncrementInvalidDevicesCount(ctx context.Context)

	// UpdateStats updates profile receiving and decoding statistics.
	UpdateStats(ctx context.Context, avgRecv, avgDec time.Duration)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementGRPCErrorCount implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementGRPCErrorCount(_ context.Context, errType GRPCError) {}

// IncrementInvalidDevicesCount implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementInvalidDevicesCount(_ context.Context) {}

// UpdateStats implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) UpdateStats(_ context.Context, _, _ time.Duration) {}
