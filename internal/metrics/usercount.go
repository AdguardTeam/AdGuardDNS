package metrics

import (
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
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

// dayMinutes contains the number of minutes in a day for convenience.
const dayMinutes = 24 * 60

// userCounter is used to save estimated counts of active users per hour and per
// day.
type userCounter struct {
	// currentMinuteCounterMu protects currentMinute and currentMinuteCounter.
	currentMinuteCounterMu *sync.Mutex

	// currentMinuteCounter is a counter for the current minute of a day.
	currentMinuteCounter *hyperloglog.Sketch

	// dayMinuteCountersMu protects dayMinuteCounters.
	dayMinuteCountersMu *sync.Mutex

	// dayMinuteCounters contains HyperLogLog counters for each minute of the
	// day.  The index of the slice is the minute of the day in the [0, 1440)
	// interval.
	dayMinuteCounters []*hyperloglog.Sketch

	// currentMinute is the current minute of the day in the [0, 1440) interval.
	currentMinute int
}

// newUserCounter initializes and returns a *userCounter.
func newUserCounter() (c *userCounter) {
	return &userCounter{
		currentMinuteCounterMu: &sync.Mutex{},
		currentMinuteCounter:   nil,
		dayMinuteCountersMu:    &sync.Mutex{},
		dayMinuteCounters:      make([]*hyperloglog.Sketch, dayMinutes),
		// Use -1 to trigger the initialization of currentMinuteCounter
		// regardless of the actual current minute of the day.
		currentMinute: -1,
	}
}

// record updates the current minute-of-the-day counter as well as sets the
// values of the hourly and daily metric counters, if necessary.  now is the
// time for which to record the IP address, typically the current time.  If
// syncUpdate is true, record performs the metric counter updates syncrhonously.
// syncUpdate is currently only used in tests.
func (c *userCounter) record(now time.Time, ip netip.Addr, syncUpdate bool) {
	minuteOfTheDay := now.Hour()*60 + now.Minute()

	// Assume that ip is the remote IP address, which has already been unmapped
	// by [netutil.NetAddrToAddrPort].
	b := ip.As16()

	c.currentMinuteCounterMu.Lock()
	defer c.currentMinuteCounterMu.Unlock()

	if c.currentMinute != minuteOfTheDay {
		prevMinute := c.currentMinute
		prevMinuteCounter := c.currentMinuteCounter

		c.currentMinute = minuteOfTheDay
		c.currentMinuteCounter = newHyperLogLog()

		// If this is the first iteration and prevMinute is -1, don't update the
		// counters, since there are none.
		if prevMinute != -1 {
			if syncUpdate {
				c.updateCounters(prevMinute, prevMinuteCounter)
			} else {
				go c.updateCounters(prevMinute, prevMinuteCounter)
			}
		}
	}

	c.currentMinuteCounter.Insert(b[:])
}

// updateCounters adds prevCounter to c.dayMinuteCounters and then merges the
// daily counters and updates the metrics.
func (c *userCounter) updateCounters(prevMinute int, prevCounter *hyperloglog.Sketch) {
	defer log.OnPanic("metrics.userCounter.updateCounters")

	c.dayMinuteCountersMu.Lock()
	defer c.dayMinuteCountersMu.Unlock()

	// Insert the previous counter into the rolling counters collection.
	c.dayMinuteCounters[prevMinute] = prevCounter

	// Calculate the estimated numbers of hourly and daily users.
	hourly, daily := c.estimate(prevMinute)

	dnsSvcUsersCount.Set(float64(hourly))
	dnsSvcUsersDailyCount.Set(float64(daily))
}

// estimate uses HyperLogLog counters to estimate the hourly and daily users
// count, starting with the minute of the day m.
func (c *userCounter) estimate(m int) (hourly, daily uint64) {
	hourlyCounter, dailyCounter := newHyperLogLog(), newHyperLogLog()

	// Go through all minutes in a day while decreasing the current minute m.
	// Decreasing m, as opposed to increasing it or using i as the minute, is
	// required to make summing the hourly statistics within the same loop
	// easier.
	for i := 0; i < dayMinutes; i++ {
		minCounter := c.dayMinuteCounters[m]
		m = decrMod(m, dayMinutes)

		if minCounter == nil {
			continue
		}

		// Use [mustMerge], since the only reason an error may be returned here
		// is when the two sketches do not have the same precisions.
		mustMerge(dailyCounter, minCounter)

		// Only include the first 60 minutes into the hourly statistics.
		if i < 60 {
			mustMerge(hourlyCounter, minCounter)
		}
	}

	return hourlyCounter.Estimate(), dailyCounter.Estimate()
}

// mustMerge panics if a.Merge(b) returns an error.
func mustMerge(a, b *hyperloglog.Sketch) {
	err := a.Merge(b)
	if err != nil {
		panic(err)
	}
}

// decrMod decreases n by one using modulus m.  That is, for n = 0 and m = 100
// it returns 99.
func decrMod(n, m int) (res int) {
	if n == 0 {
		return m - 1
	}

	return n - 1
}

// newHyperLogLog creates a new instance of hyperloglog.Sketch.
func newHyperLogLog() (sk *hyperloglog.Sketch) {
	return hyperloglog.New16()
}

// defaultUserCounter is the main user statistics counter.
var defaultUserCounter = newUserCounter()

// DNSSvcUsersCountUpdate records a visit by ip and updates the values of the
// [dnsSvcUsersCount] and [dnsSvcUsersDailyCount] gauges every second.
func DNSSvcUsersCountUpdate(ip netip.Addr) {
	defaultUserCounter.record(time.Now(), ip, false)
}
