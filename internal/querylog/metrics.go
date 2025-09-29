package querylog

import (
	"context"
	"time"

	"github.com/c2h5oh/datasize"
)

// Metrics is an interface that is used for the collection of the query log
// statistics.
type Metrics interface {
	// ObserveItemSize stores the size of written query log entry.
	ObserveItemSize(ctx context.Context, size datasize.ByteSize)

	// ObserveWrite stores the duration of the write operation and increments
	// the write counter.
	ObserveWrite(ctx context.Context, dur time.Duration)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// ObserveItemSize implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) ObserveItemSize(_ context.Context, _ datasize.ByteSize) {}

// ObserveWrite implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) ObserveWrite(_ context.Context, _ time.Duration) {}
