package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/axiomhq/hyperloglog"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// minutesPerHour is the number of minutes in an hour.
	minutesPerHour = int(time.Hour / time.Minute)

	// hoursPerDay is the number of hours in a day.
	hoursPerDay = int(timeutil.Day / time.Hour)
)

// UserCounter is used to save estimated counts of active users per hour and per
// day by some data.
//
// TODO(a.garipov):  Improve and move to golibs.
type UserCounter struct {
	// logger is used to report errors.
	logger *slog.Logger

	// lastHour is a gauge with an approximate number of DNS users for the
	// last 1 hour.
	lastHour prometheus.Gauge

	// lastDay is a gauge with an approximate number of DNS users for
	// the last 24 hours.
	lastDay prometheus.Gauge

	// currentMu protects currentMinute and currentMinuteCounter.
	currentMu *sync.Mutex

	// currentMinuteCounter is a counter for the current minute of a day.
	currentMinuteCounter *hyperloglog.Sketch

	// countersMu protects hourMinuteCounters and dayHourCounters.
	countersMu *sync.Mutex

	// hourMinuteCounters contains HyperLogLog counters for each minute of an
	// hour.  The index of the slice is the minute of the hour in the [0, 60)
	// interval.
	hourMinuteCounters *[minutesPerHour]*hyperloglog.Sketch

	// dayHourCounters contains HyperLogLog counters for each hour of a day.
	// The index of the slice is the hour of the day in the [0, 24) interval.
	dayHourCounters *[hoursPerDay]*hyperloglog.Sketch

	// currentMinute is the current minute of the day in the [0, 1440) interval.
	currentMinute int
}

// NewUserCounter initializes and returns a properly initialized *UserCounter
// that uses the given gauges to estimate the user count.  All arguments must
// not be nil.
func NewUserCounter(logger *slog.Logger, lastHour, lastDay prometheus.Gauge) (c *UserCounter) {
	return &UserCounter{
		logger:               logger,
		lastHour:             lastHour,
		lastDay:              lastDay,
		currentMu:            &sync.Mutex{},
		currentMinuteCounter: nil,
		countersMu:           &sync.Mutex{},
		hourMinuteCounters:   &[minutesPerHour]*hyperloglog.Sketch{},
		dayHourCounters:      &[hoursPerDay]*hyperloglog.Sketch{},
		// Use -1 to trigger the initialization of currentMinuteCounter
		// regardless of the actual current minute of the day.
		currentMinute: -1,
	}
}

// Record updates the current minute-of-the-day counter as well as sets the
// values of the hourly and daily metric counters, if necessary.  now is the
// time for which to Record the IP address or other data, typically the current
// time.
//
// If syncUpdate is true, Record performs the metric counter updates
// synchronously.  It is currently only used in tests.
//
// It currently assumes that it will be called at least once per day.
func (c *UserCounter) Record(ctx context.Context, now time.Time, userData []byte, syncUpdate bool) {
	hour, minute, _ := now.Clock()
	minuteOfDay := hour*minutesPerHour + minute

	c.currentMu.Lock()
	defer c.currentMu.Unlock()

	if c.currentMinute != minuteOfDay {
		prevMinute := c.currentMinute
		prevMinuteCounter := c.currentMinuteCounter

		c.currentMinute = minuteOfDay
		c.currentMinuteCounter = newHyperLogLog()

		// If this is the first iteration and prevMinute is -1, don't update the
		// counters, since there are none.
		if prevMinute != -1 {
			if syncUpdate {
				c.updateCounters(ctx, prevMinute, hour, prevMinuteCounter)
			} else {
				go c.updateCounters(ctx, prevMinute, hour, prevMinuteCounter)
			}
		}
	}

	c.currentMinuteCounter.Insert(userData)
}

// updateCounters adds prevCounter to counters and then merges them and updates
// the metrics.  It also clears all the stale hourly counters from the previous
// day.
func (c *UserCounter) updateCounters(
	ctx context.Context,
	prevMinute int,
	currentHour int,
	prevMinuteCounter *hyperloglog.Sketch,
) {
	defer slogutil.RecoverAndLog(ctx, c.logger)

	prevMinuteOfHour := prevMinute % minutesPerHour
	hourOfPrevMinute := prevMinute / minutesPerHour

	c.countersMu.Lock()
	defer c.countersMu.Unlock()

	// Insert the previous counter into the rolling counters collection.
	c.hourMinuteCounters[prevMinuteOfHour] = prevMinuteCounter
	c.updateHours(currentHour, hourOfPrevMinute, prevMinuteCounter)

	// Calculate the estimated numbers of hourly and daily users.
	hourly, daily := c.Estimate()

	c.lastHour.Set(float64(hourly))
	c.lastDay.Set(float64(daily))
}

// updateHours adds the prevMinuteCounter to the hourly counter for prevHour
// hour, and clears all the counters between curHour and prevHour, since those
// may contain data for the previous day.
func (c *UserCounter) updateHours(curHour, prevHour int, prevMinuteCounter *hyperloglog.Sketch) {
	for h := curHour; h != prevHour; h = decMod(h, hoursPerDay) {
		c.dayHourCounters[h] = nil
	}

	if c.dayHourCounters[prevHour] == nil {
		c.dayHourCounters[prevHour] = newHyperLogLog()
	}

	mustMerge(c.dayHourCounters[prevHour], prevMinuteCounter)
}

// Estimate uses HyperLogLog counters to return the number of users for the last
// hour and the last day.  It doesn't include the data for current minute.
//
// It must not be called concurrently with [UserCounter.updateCounters].
//
// TODO(a.garipov):  Unexport and use gauges instead?
func (c *UserCounter) Estimate() (hourly, daily uint64) {
	hourlyCounter, dailyCounter := newHyperLogLog(), newHyperLogLog()

	for _, c := range c.hourMinuteCounters {
		if c != nil {
			mustMerge(hourlyCounter, c)
		}
	}

	for _, c := range c.dayHourCounters {
		if c != nil {
			mustMerge(dailyCounter, c)
		}
	}

	return hourlyCounter.Estimate(), dailyCounter.Estimate()
}

// mustMerge panics if [hyperloglog.Sketch.Merge] returns an error.
func mustMerge(a, b *hyperloglog.Sketch) {
	err := a.Merge(b)
	if err != nil {
		panic(err)
	}
}

// newHyperLogLog creates a new instance of hyperloglog.Sketch with precision 18
// and sparse mode enabled.
func newHyperLogLog() (sk *hyperloglog.Sketch) {
	sk, err := hyperloglog.NewSketch(18, true)
	if err != nil {
		// Should never happen, as NewSketch only returns an error when the
		// precision is out of range.
		panic(fmt.Errorf("metrics.UserCounter.Record: unexpected error: %w", err))
	}

	return sk
}

// decMod decreases n by one using modulus m.  That is, for n = 0 and m = 100 it
// returns 99.  n should be in the [0, m) interval.
func decMod(n, m int) (res int) {
	if n == 0 {
		return m - 1
	}

	return n - 1
}
