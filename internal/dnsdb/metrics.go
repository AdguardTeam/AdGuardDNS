package dnsdb

import (
	"context"
	"time"
)

// Metrics is an interface that is used for the collection of the DNS database
// statistics.
type Metrics interface {
	// SetRecordCount sets the number of records that have not yet been
	// uploaded.
	SetRecordCount(ctx context.Context, count int)

	// ObserveRotation updates the time of the database rotation and stores the
	// duration of the rotation.
	ObserveRotation(ctx context.Context, dur time.Duration)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// SetRecordCount implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetRecordCount(_ context.Context, _ int) {}

// ObserveRotation implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) ObserveRotation(_ context.Context, dur time.Duration) {}
