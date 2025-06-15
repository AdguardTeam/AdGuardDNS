package access

import (
	"context"
	"time"
)

// ProfileMetrics is an interface used for collecting statistics related to the
// profile access engine.
type ProfileMetrics interface {
	// ObserveProfileInit records the duration taken for the initialization of
	// the profile access engine.
	ObserveProfileInit(ctx context.Context, dur time.Duration)
}

// EmptyProfileMetrics is the implementation of the [ProfileMetrics] interface
// that does nothing.
type EmptyProfileMetrics struct{}

// type check
var _ ProfileMetrics = EmptyProfileMetrics{}

// ObserveProfileInit implements the [ProfileMetrics] interface for
// EmptyProfileMetrics.
func (EmptyProfileMetrics) ObserveProfileInit(_ context.Context, _ time.Duration) {}
