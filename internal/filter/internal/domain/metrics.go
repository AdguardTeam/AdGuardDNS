package domain

import (
	"context"
)

// Metrics is an interface used for collection if the domain filter
// statistics.
type Metrics interface {
	// IncrementLookups increments the number of lookups.  hit is true if the
	// lookup returned a value.
	IncrementLookups(ctx context.Context, hit bool)

	// UpdateCacheSize is called when the cache size is updated.
	UpdateCacheSize(ctx context.Context, cacheLen int)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementLookups implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementLookups(_ context.Context, _ bool) {}

// UpdateCacheSize implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) UpdateCacheSize(_ context.Context, _ int) {}
