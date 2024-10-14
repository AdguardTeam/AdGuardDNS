package profiledb

import (
	"context"
	"time"
)

// Metrics is an interface that is used for the collection of the user profiles
// statistics.
type Metrics interface {
	// HandleProfilesUpdate handles the user profile update.  m must not be nil.
	HandleProfilesUpdate(ctx context.Context, m *UpdateMetrics)

	// SetProfilesAndDevicesNum sets the total number of user profiles and the
	// total number of devices.
	SetProfilesAndDevicesNum(ctx context.Context, profNum, devNum uint)

	// IncrementSyncTimeouts increments the total number of timeout errors
	// during user profile update.
	IncrementSyncTimeouts(ctx context.Context, isFullSync bool)

	// IncrementDeleted increments the total number of deleted user profiles.
	IncrementDeleted(ctx context.Context)
}

// UpdateMetrics is an alias for a structure that contains the information about
// a user profiles update operation.
//
// NOTE:  This is an alias to reduce the amount of dependencies required of
// implementations.  This is also the reason why only built-in or stdlib types
// are used.
type UpdateMetrics = struct {
	// Duration is the duration of the user profiles update operation.
	Duration time.Duration

	// ProfilesNum is the total number of updated profiles.
	ProfilesNum uint

	// DevicesNum is the total number of updated devices.
	DevicesNum uint

	// IsSuccess indicates whether the update was successful.
	IsSuccess bool

	// IsFullSync indicates whether the update was full or partial.
	IsFullSync bool
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// HandleProfilesUpdate implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) HandleProfilesUpdate(_ context.Context, _ *UpdateMetrics) {}

// SetProfilesAndDevicesNum implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetProfilesAndDevicesNum(_ context.Context, _, _ uint) {}

// IncrementSyncTimeouts implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementSyncTimeouts(_ context.Context, _ bool) {}

// IncrementDeleted implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementDeleted(_ context.Context) {}
