package ecscache

import "context"

// Metrics is an interface that is used for the collection of the ECS cache
// statistics.
type Metrics interface {
	// SetElementsCount sets the total number of items in the cache for domain
	// names that support or do not support ECS.
	SetElementsCount(ctx context.Context, supportsECS bool, count int)

	// IncrementLookups increments the number of ECS cache lookups for hosts
	// that does or doesn't support ECS.
	IncrementLookups(ctx context.Context, supportsECS, hit bool)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// SetElementsCount implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetElementsCount(_ context.Context, _ bool, _ int) {}

// IncrementLookups implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementLookups(_ context.Context, _, _ bool) {}
