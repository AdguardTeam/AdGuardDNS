package billstat

import "context"

// Metrics is an interface that is used for the collection of the billing
// statistics.
type Metrics interface {
	// SetRecordCount sets the total number of records stored.
	SetRecordCount(ctx context.Context, count int)

	// HandleUploadDuration handles the upload duration of billing statistics.
	HandleUploadDuration(ctx context.Context, dur float64, err error)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// SetRecordCount implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetRecordCount(_ context.Context, _ int) {}

// HandleUploadDuration implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) HandleUploadDuration(_ context.Context, _ float64, _ error) {}
