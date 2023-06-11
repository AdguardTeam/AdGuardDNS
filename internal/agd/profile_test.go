package agd_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
)

func TestDayRange_Validate(t *testing.T) {
	testCases := []struct {
		name       string
		wantErrMsg string
		rng        agd.DayRange
	}{{
		name:       "ok",
		wantErrMsg: "",
		rng:        agd.DayRange{Start: 11 * 60, End: 13*60 - 1},
	}, {
		name:       "ok_zeroes",
		wantErrMsg: "",
		rng:        agd.DayRange{Start: 0, End: 0},
	}, {
		name:       "ok_max",
		wantErrMsg: "",
		rng: agd.DayRange{
			Start: agd.MaxDayRangeMinutes,
			End:   agd.MaxDayRangeMinutes,
		},
	}, {
		name:       "ok_zero_length",
		wantErrMsg: "",
		rng:        agd.ZeroLengthDayRange(),
	}, {
		name:       "err_before",
		wantErrMsg: "bad day range: end 0 less than start 1",
		rng:        agd.DayRange{Start: 1, End: 0},
	}, {
		name:       "err_bad_start",
		wantErrMsg: "bad day range: start 10000 greater than 1439",
		rng:        agd.DayRange{Start: 10_000, End: 10_000},
	}, {
		name:       "err_bad_end",
		wantErrMsg: "bad day range: end 10000 greater than 1439",
		rng:        agd.DayRange{Start: 0, End: 10_000},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rng.Validate()
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestParentalProtectionSchedule_Contains(t *testing.T) {
	baseTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	otherTime := baseTime.Add(1 * timeutil.Day)

	// NOTE: In the Etc area the sign of the offsets is flipped.  So, Etc/GMT-3
	// is actually UTC+03:00.
	otherTZ := time.FixedZone("Etc/GMT-3", 3*60*60)

	// baseSchedule, 12:00:00 to 13:59:59.
	baseSchedule := &agd.ParentalProtectionSchedule{
		Week: &agd.WeeklySchedule{
			time.Sunday:    agd.ZeroLengthDayRange(),
			time.Monday:    agd.ZeroLengthDayRange(),
			time.Tuesday:   agd.ZeroLengthDayRange(),
			time.Wednesday: agd.ZeroLengthDayRange(),
			time.Thursday:  agd.ZeroLengthDayRange(),

			// baseTime is on Friday.
			time.Friday: agd.DayRange{12 * 60, 14*60 - 1},

			time.Saturday: agd.ZeroLengthDayRange(),
		},
		TimeZone: agdtime.UTC(),
	}

	// allDaySchedule, 00:00:00 to 23:59:59.
	allDaySchedule := &agd.ParentalProtectionSchedule{
		Week: &agd.WeeklySchedule{
			time.Sunday:    agd.ZeroLengthDayRange(),
			time.Monday:    agd.ZeroLengthDayRange(),
			time.Tuesday:   agd.ZeroLengthDayRange(),
			time.Wednesday: agd.ZeroLengthDayRange(),
			time.Thursday:  agd.ZeroLengthDayRange(),

			// baseTime is on Friday.
			time.Friday: agd.DayRange{0, 24*60 - 1},

			time.Saturday: agd.ZeroLengthDayRange(),
		},
		TimeZone: agdtime.UTC(),
	}

	testCases := []struct {
		schedule *agd.ParentalProtectionSchedule
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
		assert:   assert.False,
		t:        baseTime.Add(11 * time.Hour),
		name:     "same_day_outside",
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
			tc.assert(t, tc.schedule.Contains(tc.t))
		})
	}
}
