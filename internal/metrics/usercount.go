package metrics

import (
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/axiomhq/hyperloglog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// dnsSvcUsersCount is a gauge with an approximate number of DNS users for the
// last 1 hour.
var dnsSvcUsersCount = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "users_last_hour_count",
	Namespace: namespace,
	Subsystem: subsystemDNSSvc,
	Help:      "The approximate number of DNS users for the last 1 hour.",
})

// dnsSvcUsersDailyCount is a gauge with an approximate number of DNS users for
// the last 24 hours.
var dnsSvcUsersDailyCount = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "users_last_day_count",
	Namespace: namespace,
	Subsystem: subsystemDNSSvc,
	Help:      "The approximate number of DNS users for the last 24 hours.",
})

const (
	// minutesPerHour is the number of minutes in an hour.
	minutesPerHour = int(time.Hour / time.Minute)

	// hoursPerDay is the number of hours in a day.
	hoursPerDay = int(timeutil.Day / time.Hour)
)

// userCounter is used to save estimated counts of active users per hour and per
// day.
type userCounter struct {
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

// newUserCounter initializes and returns a *userCounter.
func newUserCounter() (c *userCounter) {
	return &userCounter{
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

// record updates the current minute-of-the-day counter as well as sets the
// values of the hourly and daily metric counters, if necessary.  now is the
// time for which to record the IP address, typically the current time.
//
// If syncUpdate is true, record performs the metric counter updates
// synchronously.  It's is currently only used in tests.
//
// It currently assumes that it will be called at least once per day.
func (c *userCounter) record(now time.Time, ip netip.Addr, syncUpdate bool) {
	hour, minute, _ := now.Clock()
	minuteOfDay := hour*minutesPerHour + minute

	// Assume that ip is the remote IP address, which has already been unmapped
	// by [netutil.NetAddrToAddrPort].
	b := ip.As16()

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
				c.updateCounters(prevMinute, hour, prevMinuteCounter)
			} else {
				go c.updateCounters(prevMinute, hour, prevMinuteCounter)
			}
		}
	}

	c.currentMinuteCounter.Insert(b[:])
}

// updateCounters adds prevCounter to counters and then merges them and updates
// the metrics.  It also clears all the stale hourly counters from the previous
// day.
func (c *userCounter) updateCounters(
	prevMinute int,
	currentHour int,
	prevMinuteCounter *hyperloglog.Sketch,
) {
	defer log.OnPanic("metrics.userCounter.updateCounters")

	prevMinuteOfHour := prevMinute % minutesPerHour
	hourOfPrevMinute := prevMinute / minutesPerHour

	c.countersMu.Lock()
	defer c.countersMu.Unlock()

	// Insert the previous counter into the rolling counters collection.
	c.hourMinuteCounters[prevMinuteOfHour] = prevMinuteCounter
	c.updateHours(currentHour, hourOfPrevMinute, prevMinuteCounter)

	// Calculate the estimated numbers of hourly and daily users.
	hourly, daily := c.estimate()

	dnsSvcUsersCount.Set(float64(hourly))
	dnsSvcUsersDailyCount.Set(float64(daily))
}

// updateHours adds the prevMinuteCounter to the hourly counter for prevHour
// hour, and clears all the counters between curHour and prevHour, since those
// may contain data for the previous day.
func (c *userCounter) updateHours(curHour, prevHour int, prevMinuteCounter *hyperloglog.Sketch) {
	for h := curHour; h != prevHour; h = decMod(h, hoursPerDay) {
		c.dayHourCounters[h] = nil
	}

	if c.dayHourCounters[prevHour] == nil {
		c.dayHourCounters[prevHour] = newHyperLogLog()
	}

	mustMerge(c.dayHourCounters[prevHour], prevMinuteCounter)
}

// estimate uses HyperLogLog counters to return the number of users for the last
// hour and the last day.  It doesn't include the data for current minute.  It
// must not be called concurrently with [userCounter.updateCounters].
func (c *userCounter) estimate() (hourly, daily uint64) {
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

// hyperloglogConfig is a serialized [hyperLogLog.Sketch] with precision 18 and
// sparse mode enabled.
var hyperloglogConfig = [20]byte{
	// Version.
	0: 0x1,
	// Precision.
	1: 18,
	// Sparse.
	3: 0x1,
}

// newHyperLogLog creates a new instance of hyperloglog.Sketch with precision 18
// and sparse mode enabled.
func newHyperLogLog() (sk *hyperloglog.Sketch) {
	sk = &hyperloglog.Sketch{}
	err := sk.UnmarshalBinary(hyperloglogConfig[:])
	if err != nil {
		// Generally shouldn't happen.
		panic(err)
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

// defaultUserCounter is the main user statistics counter.
var defaultUserCounter = newUserCounter()

// DNSSvcUsersCountUpdate records a visit by ip and updates the values of the
// [dnsSvcUsersCount] and [dnsSvcUsersDailyCount] gauges every second.
func DNSSvcUsersCountUpdate(ip netip.Addr) {
	defaultUserCounter.record(time.Now(), ip, false)
}
