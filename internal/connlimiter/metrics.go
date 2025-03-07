package connlimiter

import (
	"context"
	"time"
)

// Metrics is an interface used for collection of the stream-connections
// statistics.
type Metrics interface {
	// IncrementActive increments the number of active stream-connections.  m
	// must not be nil.
	IncrementActive(ctx context.Context, m *ConnMetricsData)

	// DecrementActive decrements the number of active stream-connections.  m
	// must not be nil.
	DecrementActive(ctx context.Context, m *ConnMetricsData)

	// ObserveLifeDuration updates the duration of life times for
	// stream-connections.  m must not be nil.
	ObserveLifeDuration(ctx context.Context, m *ConnMetricsData, dur time.Duration)

	// ObserveWaitingDuration updates the duration of waiting times for
	// accepting stream-connections.  m must not be nil.
	ObserveWaitingDuration(ctx context.Context, m *ConnMetricsData, dur time.Duration)

	// SetStopLimit sets the stopping limit number of active stream-connections.
	SetStopLimit(ctx context.Context, n uint64)

	// SetResumeLimit sets the resuming limit number of active
	// stream-connections.
	SetResumeLimit(ctx context.Context, n uint64)
}

// ConnMetricsData is an alias for a structure that contains the information
// about a stream-connection.  All fields must not be empty.
//
// NOTE:  This is an alias to reduce the amount of dependencies required of
// implementations.  This is also the reason why only built-in or stdlib types
// are used.
type ConnMetricsData = struct {
	// Addr is the address that the server is configured to listen on.
	Addr string

	// Name is the name of the server.
	Name string

	// Proto is the protocol of the server.
	Proto string
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementActive implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementActive(_ context.Context, _ *ConnMetricsData) {}

// DecrementActive implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) DecrementActive(_ context.Context, _ *ConnMetricsData) {}

// ObserveLifeDuration implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) ObserveLifeDuration(_ context.Context, _ *ConnMetricsData, _ time.Duration) {}

// ObserveWaitingDuration implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) ObserveWaitingDuration(_ context.Context, _ *ConnMetricsData, _ time.Duration) {}

// SetStopLimit implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetStopLimit(_ context.Context, _ uint64) {}

// SetResumeLimit implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetResumeLimit(_ context.Context, _ uint64) {}
