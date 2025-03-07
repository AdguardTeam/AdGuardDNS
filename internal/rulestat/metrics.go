package rulestat

import (
	"context"
)

// Metrics is an interface that is used for the collection of the filtering rule
// statistics.
type Metrics interface {
	// SetHitCount the number of rule hits that have not yet been uploaded.
	SetHitCount(ctx context.Context, count int64)

	// HandleUploadStatus handles the upload status of the filtering rule
	// statistics.
	HandleUploadStatus(ctx context.Context, err error)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// SetHitCount implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetHitCount(_ context.Context, _ int64) {}

// HandleUploadStatus implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) HandleUploadStatus(_ context.Context, _ error) {}
