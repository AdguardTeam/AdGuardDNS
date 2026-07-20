package filter_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
)

func TestDayInterval_Validate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		ivl        *filter.DayInterval
		name       string
		wantErrMsg string
	}{{
		ivl: &filter.DayInterval{
			Start: 11 * 60,
			End:   13*60 - 1,
		},
		name:       "ok",
		wantErrMsg: "",
	}, {
		ivl: &filter.DayInterval{
			Start: 0,
			End:   0,
		},
		name:       "ok_zeroes",
		wantErrMsg: "",
	}, {
		ivl:        nil,
		name:       "ok_nil",
		wantErrMsg: "",
	}, {
		ivl: &filter.DayInterval{
			Start: filter.MaxDayIntervalStartMinutes,
			End:   filter.MaxDayIntervalEndMinutes,
		},
		name:       "ok_max",
		wantErrMsg: "",
	}, {
		ivl: &filter.DayInterval{
			Start: 1,
			End:   0,
		},
		name:       "err_before",
		wantErrMsg: "end: out of range: 0 is less than start 1",
	}, {
		ivl: &filter.DayInterval{
			Start: 10_000,
			End:   10_000,
		},
		name:       "err_bad_start",
		wantErrMsg: "start: out of range: 10000 is greater than 1439",
	}, {
		ivl: &filter.DayInterval{
			Start: 0,
			End:   10_000,
		},
		name:       "err_bad_end",
		wantErrMsg: "end: out of range: 10000 is greater than 1440",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.ivl.Validate()
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDayIntervals_Validate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		wantErrMsg string
		ivls       filter.DayIntervals
	}{{
		ivls: filter.DayIntervals{
			{Start: 0, End: 13 * 60},
			{Start: 13 * 60, End: 14*60 - 1},
		},
		name:       "ok",
		wantErrMsg: "",
	}, {
		ivls: filter.DayIntervals{
			{Start: 0, End: 0},
			{Start: 0, End: 0},
		},
		name:       "ok_zeroes",
		wantErrMsg: "",
	}, {
		ivls: filter.DayIntervals{
			nil,
			nil,
		},
		name:       "ok_nil",
		wantErrMsg: "",
	}, {
		ivls: filter.DayIntervals{
			nil,
			{Start: 13 * 60, End: 14 * 60},
		},
		name:       "ok_partially_nil",
		wantErrMsg: "",
	}, {
		ivls: filter.DayIntervals{
			{Start: 12 * 60, End: 13*60 + 1},
			{Start: 13 * 60, End: 14 * 60},
		},
		name:       "err_intervals_overlap",
		wantErrMsg: "intervals overlap: first interval end: 13:01, second interval start: 13:00",
	}, {
		ivls: filter.DayIntervals{
			{Start: 13 * 60, End: 15 * 60},
			{Start: 13 * 60, End: 14 * 60},
		},
		name:       "err_intervals_start_overlap",
		wantErrMsg: "intervals overlap: identical start time: 13:00",
	}, {
		ivls: filter.DayIntervals(make([]*filter.DayInterval, filter.MaxDayIntervalEndMinutes+1)),
		name: "err_too_many_intervals",
		wantErrMsg: fmt.Sprintf(
			"day_intervals_len: out of range: must be no greater than %d, got %d",
			filter.MaxDayIntervalEndMinutes,
			filter.MaxDayIntervalEndMinutes+1,
		),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.ivls.Validate()
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestFilterConfigSchedule_Contains(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	otherTime := baseTime.Add(1 * timeutil.Day)

	// NOTE: In the Etc area the sign of the offsets is flipped.  So, Etc/GMT-3
	// is actually UTC+03:00.
	otherTZ := time.FixedZone("Etc/GMT-3", 3*60*60)

	// baseSchedule, 10:00:00 to 11:00:00 and 12:00:00 to 13:59:59.
	baseSchedule := &filter.ConfigSchedule{
		Week: &filter.WeeklySchedule{
			// baseTime is on Friday.
			time.Friday: filter.DayIntervals{
				&filter.DayInterval{
					Start: 8 * 60,
					End:   10 * 60,
				},
				&filter.DayInterval{
					Start: 12 * 60,
					End:   14 * 60,
				},
			},
		},
		TimeZone: agdtime.UTC(),
	}

	// allDaySchedule, 00:00:00 to 23:59:59.
	allDaySchedule := &filter.ConfigSchedule{
		Week: &filter.WeeklySchedule{
			// baseTime is on Friday.
			time.Friday: filter.DayIntervals{
				&filter.DayInterval{
					Start: 0,
					End:   filter.MaxDayIntervalEndMinutes,
				},
			},
		},
		TimeZone: agdtime.UTC(),
	}

	testCases := []struct {
		schedule *filter.ConfigSchedule
		assert   assert.BoolAssertionFunc
		t        time.Time
		name     string
	}{{
		schedule: allDaySchedule,
		assert:   assert.True,
		t:        baseTime,
		name:     "same_day_all_day",
	}, {
		schedule: baseSchedule,
		assert:   assert.True,
		t:        baseTime.Add(13 * time.Hour),
		name:     "same_day_inside",
	}, {
		schedule: baseSchedule,
		assert:   assert.True,
		t:        baseTime.Add(12 * time.Hour),
		name:     "same_day_start",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        baseTime.Add(14 * time.Hour),
		name:     "same_day_end",
	}, {
		schedule: baseSchedule,
		assert:   assert.True,
		t:        baseTime.Add(14 * time.Hour).Add(-1),
		name:     "same_day_almost_end",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        baseTime.Add(11 * time.Hour),
		name:     "same_day_outside_between",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        baseTime.Add(16 * time.Hour),
		name:     "same_day_outside_after",
	}, {
		schedule: allDaySchedule,
		assert:   assert.False,
		t:        otherTime,
		name:     "other_day_all_day",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        otherTime.Add(13 * time.Hour),
		name:     "other_day_inside",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        otherTime.Add(11 * time.Hour),
		name:     "other_day_outside",
	}, {
		schedule: baseSchedule,
		assert:   assert.True,
		t:        baseTime.Add(13 * time.Hour).In(otherTZ),
		name:     "same_day_inside_other_tz",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        baseTime.Add(11 * time.Hour).In(otherTZ),
		name:     "same_day_outside_other_tz",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.schedule.Contains(tc.t))
		})
	}
}
