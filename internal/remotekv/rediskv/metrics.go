package rediskv

import "context"

// Metrics is an interface that is used for the collection of the Redis KV
// statistics.
type Metrics interface {
	// UpdateMetrics updates the total number of active connections and
	// increments the total number of errors if necessary.
	UpdateMetrics(ctx context.Context, val uint, isSuccess bool)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// UpdateMetrics implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) UpdateMetrics(_ context.Context, _ uint, _ bool) {}
