package filter

import (
	"context"
	"time"
)

// TODO(a.garipov):  Consider re-adding some metrics for custom filters after
// AGDNS-1519.

// Metrics is the interface for metrics of filters.
type Metrics interface {
	// SetStatus sets the status of a filter by its ID.  If err is not nil,
	// updTime and ruleCount are ignored.
	SetStatus(
		ctx context.Context,
		id string,
		updTime time.Time,
		ruleCount uint64,
		err error,
	)

	// Delete removes any data about the filters with the given IDs.
	Delete(ctx context.Context, ids []string)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// SetStatus implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetStatus(_ context.Context, _ string, _ time.Time, _ uint64, _ error) {}

// Delete implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) Delete(_ context.Context, _ []string) {}
