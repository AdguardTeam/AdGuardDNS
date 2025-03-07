package filter

import (
	"context"
	"time"
)

// TODO(a.garipov):  Consider re-adding some metrics for custom filters after
// AGDNS-1519.

// Metrics is the interface for metrics of filters.
type Metrics interface {
	// SetFilterStatus sets the status of a filter by its id.  If err is not
	// nil, updTime and ruleCount are ignored.
	SetFilterStatus(
		ctx context.Context,
		id string,
		updTime time.Time,
		ruleCount int,
		err error,
	)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// SetFilterStatus implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetFilterStatus(_ context.Context, _ string, _ time.Time, _ int, _ error) {}
