package agdtime

import (
	"time"

	"github.com/AdguardTeam/golibs/timeutil"
)

// ExponentialSchedule is a [timeutil.Schedule] that exponentially increases the
// time until the next event until it reaches the maximum.
//
// TODO(a.garipov):  Consider moving to golibs.
type ExponentialSchedule struct {
	current time.Duration
	max     time.Duration
	base    uint64
}

// NewExponentialSchedule returns a new properly initialized
// *ExponentialSchedule.
func NewExponentialSchedule(initial, max time.Duration, base uint64) (s *ExponentialSchedule) {
	return &ExponentialSchedule{
		current: initial,
		max:     max,
		base:    base,
	}
}

// type check
var _ timeutil.Schedule = (*ExponentialSchedule)(nil)

// UntilNext implements the [timeutil.Schedule] interface for
// *ExponentialSchedule.
func (s *ExponentialSchedule) UntilNext(_ time.Time) (d time.Duration) {
	d = s.current

	// A negative s.current means that the previous call has overflown
	// time.Duration, which means it's above max.
	if d >= s.max || d < 0 {
		return s.max
	}

	// #nosec G115 -- The overflow is processed above.
	s.current = s.current * time.Duration(s.base)

	return d
}
