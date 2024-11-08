package consul

import "context"

// Metrics is an interface that is used for the collection of the allowlist
// statistics.
type Metrics interface {
	// SetSize sets the number of received subnets.
	SetSize(ctx context.Context, n int)

	// SetStatus sets the status and time of the allowlist refresh attempt.
	SetStatus(ctx context.Context, err error)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// SetSize implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetSize(_ context.Context, _ int) {}

// SetStatus plements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetStatus(_ context.Context, _ error) {}
