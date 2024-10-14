package billstat

import "context"

// Metrics is an interface that is used for the collection of the billing
// statistics.
type Metrics interface {
	// BufferSizeSet sets the number of stored records to n.
	BufferSizeSet(ctx context.Context, n float64)

	// HandleUploadDuration handles the upload duration of billing statistics.
	HandleUploadDuration(ctx context.Context, dur float64, isSuccess bool)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// BufferSizeSet implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) BufferSizeSet(_ context.Context, _ float64) {}

// HandleUploadDuration implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) HandleUploadDuration(_ context.Context, _ float64, _ bool) {}
