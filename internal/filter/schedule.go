package filter

import (
	"fmt"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// DayInterval is an interval within a single day.  The interval is inclusive at
// the start and exclusive at the end.  An empty DayInterval is zero-length.
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

// DayIntervals represents multiple [DayInterval] values within a single day.
type DayIntervals []*DayInterval

// type check
var _ validate.Interface = DayIntervals(nil)

// Validate returns validation errors, if any, of all intervals within
// DayIntervals.  A nil DayIntervals object is considered valid.
//
// TODO(m.kazantsev):  Consider requiring the slices to have already been
// sorted.
func (d DayIntervals) Validate() (err error) {
	if d == nil {
		return nil
	}

	dLen := len(d)
	if dLen == 1 {
		err = d[0].Validate()

		return err
	}

	ivls := make(DayIntervals, 0, dLen)

	err = validate.NoGreaterThan("day_intervals_len", dLen, MaxDayIntervalEndMinutes)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	for _, ivl := range d {
		if ivl.IsZero() {
			continue
		}

		err = ivl.Validate()
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return err
		}

		ivls = append(ivls, ivl)
	}

	sortIntervals(ivls)

	return validateOverlaps(ivls)
}

// sortIntervals calls the [slices.SortFunc] function to sort the ivls slice.
func sortIntervals(ivls []*DayInterval) {
	slices.SortFunc(ivls, func(a, b *DayInterval) int {
		if a.Start < b.Start {
			return -1
		}

		if a.Start > b.Start {
			return 1
		}

		// The checks below are performed just to avoid undefined positions of
		// elements inside ivls with identical start positions.
		if a.End < b.End {
			return -1
		}

		if a.End > b.End {
			return 1
		}

		return 0
	})
}

// validateOverlaps checks whether ivls overlap. If they do, an error is
// returned.
func validateOverlaps(ivls []*DayInterval) (err error) {
	for i := 1; i < len(ivls); i++ {
		prev := ivls[i-1]
		curr := ivls[i]

		if curr.Start == prev.Start {
			return fmt.Errorf(
				"intervals overlap: identical start time: %s",
				formatMinutesToTime(curr.Start),
			)
		}

		if curr.Start < prev.End {
			return fmt.Errorf(
				"intervals overlap: first interval end: %s, second interval start: %s",
				formatMinutesToTime(prev.End),
				formatMinutesToTime(curr.Start),
			)
		}
	}

	return nil
}

// formatMinutesToTime formats mCount to a "hh:mm" time format
func formatMinutesToTime(mCount uint16) (s string) {
	return fmt.Sprintf("%02d:%02d", mCount/60, mCount%60)
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
	case r.IsZero():
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

// IsZero checks whether r is nil or empty.
func (r *DayInterval) IsZero() (ok bool) {
	return r == nil || *r == (DayInterval{})
}

// WeeklySchedule is a schedule for one week.  The index is the same as
// [time.Weekday] values.  That is, 0 is Sunday, 1 is Monday, etc.  A nil
// DayIntervals object means that there is no schedule for this day.
type WeeklySchedule [7]DayIntervals

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
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, &s.TimeZone.Location)

	for _, ivl := range r {
		if ivl.IsZero() {
			continue
		}

		start := day.Add(time.Duration(ivl.Start) * time.Minute)
		end := day.Add(time.Duration(ivl.End) * time.Minute)

		if !t.Before(start) && t.Before(end) {
			return true
		}
	}

	return false
}
