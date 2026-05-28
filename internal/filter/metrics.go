package filter

import (
	"context"
	"time"
)

// TODO(a.garipov):  Consider re-adding some metrics for custom filters after
// AGDNS-1519.

// StatusUpdate contains the data for a filter status update.
type StatusUpdate struct {
	// Error is the error occurred during the update, if any.
	Error error

	// UpdateTime is the time of the update.
	UpdateTime time.Time

	// ID is the identifier of the filter or category filter.
	ID string

	// RuleCount is the number of rules loaded by the filter.
	RuleCount uint64

	// SizeBytes is the size of the filter data in bytes.
	SizeBytes uint64
}

// Metrics is the interface for metrics of filters.
type Metrics interface {
	// SetStatus sets the status of a filter by its ID.  update must not be nil,
	// if update.Error is not nil, update.UpdateTime, update.RuleCount, and
	// update.SizeBytes are ignored.
	SetStatus(ctx context.Context, update *StatusUpdate)

	// Delete removes any data about the filters with the given IDs.
	Delete(ctx context.Context, ids []string)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// SetStatus implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetStatus(_ context.Context, _ *StatusUpdate) {}

// Delete implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) Delete(_ context.Context, _ []string) {}
