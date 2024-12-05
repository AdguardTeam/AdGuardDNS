package filter

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/golibs/errors"
)

// DayInterval is an interval within a single day.  The interval is exclusive at
// the end.  An empty DayInterval is zero-length.
type DayInterval struct {
	// Start is the inclusive start of the interval in minutes.  It must be
	// within the range from 00:00:00 (0) to 23:59:59
	// ([MaxDayIntervalStartMinutes]).
	Start uint16

	// End is the exclusive end of the interval in minutes.  It must be within
	// the range from 00:00:00 (0) to 00:00:00 of the next day
	// ([MaxDayIntervalEndMinutes]).
	End uint16
}

const (
	// MaxDayIntervalStartMinutes is the maximum value for [DayInterval.Start].
	MaxDayIntervalStartMinutes = 24*60 - 1

	// MaxDayIntervalEndMinutes is the maximum value for [DayInterval.End].
	MaxDayIntervalEndMinutes = 24 * 60
)

// Validate returns the day range validation errors, if any.  A nil DayInterval
// is considered valid.
func (r *DayInterval) Validate() (err error) {
	switch {
	case r == nil, *r == DayInterval{}:
		return nil
	case r.End < r.Start:
		return fmt.Errorf(
			"end: %w: %d is less than start %d",
			errors.ErrOutOfRange,
			r.End,
			r.Start,
		)
	case r.Start > MaxDayIntervalStartMinutes:
		return fmt.Errorf(
			"start: %w: %d is greater than %d",
			errors.ErrOutOfRange,
			r.Start,
			MaxDayIntervalStartMinutes,
		)
	case r.End > MaxDayIntervalEndMinutes:
		return fmt.Errorf(
			"end: %w: %d is greater than %d",
			errors.ErrOutOfRange,
			r.End,
			MaxDayIntervalEndMinutes,
		)
	default:
		return nil
	}
}

// WeeklySchedule is a schedule for one week.  The index is the same as
// [time.Weekday] values.  That is, 0 is Sunday, 1 is Monday, etc.  A nil
// DayInterval means that there is no schedule for this day.
type WeeklySchedule [7]*DayInterval

// ConfigSchedule is the schedule of a client's parental protection.  All
// fields must not be nil.
type ConfigSchedule struct {
	// Week is the parental protection schedule for every day of the week.  It
	// must not be nil.
	Week *WeeklySchedule

	// TimeZone is the profile's time zone.  It must not be nil.
	TimeZone *agdtime.Location
}

// Contains returns true if t is within the allowed schedule.
func (s *ConfigSchedule) Contains(t time.Time) (ok bool) {
	t = t.In(&s.TimeZone.Location)
	r := s.Week[int(t.Weekday())]
	if r == nil || *r == (DayInterval{}) {
		return false
	}

	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, &s.TimeZone.Location)
	start := day.Add(time.Duration(r.Start) * time.Minute)
	end := day.Add(time.Duration(r.End) * time.Minute)

	return !t.Before(start) && t.Before(end)
}
