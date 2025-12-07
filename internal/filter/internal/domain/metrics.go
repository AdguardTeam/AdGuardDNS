package domain

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
)

// Metrics is an interface used for collection if the domain filter
// statistics.
type Metrics interface {
	// IncrementLookups increments the number of lookups.  hit is true if the
	// lookup returned a value.  categoryID must be a valid label name.
	IncrementLookups(ctx context.Context, categoryID filter.CategoryID, hit bool)

	// UpdateCacheSize is called when the cache size is updated.  categoryID
	// must be a valid label name.
	UpdateCacheSize(ctx context.Context, categoryID filter.CategoryID, cacheLen int)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementLookups implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementLookups(_ context.Context, _ filter.CategoryID, _ bool) {}

// UpdateCacheSize implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) UpdateCacheSize(_ context.Context, _ filter.CategoryID, _ int) {}
