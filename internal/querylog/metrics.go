package querylog

import (
	"context"
	"time"

	"github.com/c2h5oh/datasize"
)

// Metrics is an interface that is used for the collection of the query log
// statistics.
type Metrics interface {
	// IncrementItemsCount increments the total number of query log entries
	// written.
	IncrementItemsCount(ctx context.Context)

	// ObserveItemSize stores the size of written query log entry.
	ObserveItemSize(ctx context.Context, size datasize.ByteSize)

	// ObserveWriteDuration stores the duration of the write operation.
	ObserveWriteDuration(ctx context.Context, dur time.Duration)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementItemsCount implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementItemsCount(_ context.Context) {}

// ObserveItemSize implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) ObserveItemSize(_ context.Context, _ datasize.ByteSize) {}

// ObserveWriteDuration implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) ObserveWriteDuration(_ context.Context, _ time.Duration) {}
