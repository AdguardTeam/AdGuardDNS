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
	// lock protects all fields below.
	lock *sync.Mutex

	// dailyMinuteCounters contains HyperLogLog counters for each minute of the
	// day.  The index of the slice is the minute of the day in the [0, 1440)
	// interval.
	dailyMinuteCounters []*hyperloglog.Sketch

	// currentUnixSecond is used to check if the hourly and daily user counts
	// need updating.
	currentUnixSecond int64

	// currentMinute is used to check if the current minute counter of
	// dailyMinuteCounts requires resetting.
	currentMinute int64
}

// newUserCounter initializes and returns a *userCounter.
func newUserCounter() (c *userCounter) {
	return &userCounter{
		lock:                &sync.Mutex{},
		dailyMinuteCounters: make([]*hyperloglog.Sketch, dayMinutes),
		currentUnixSecond:   -1,
		currentMinute:       -1,
	}
}

// record updates the values of the hourly and daily counters.
func (c *userCounter) record(ip netip.Addr) {
	now := time.Now().UTC()
	unixSecond := now.Unix()
	minuteOfTheDay := int64(now.Hour()*60 + now.Minute())

	// Assume that ip is the remote IP address, which has already been unmapped
	// by [netutil.NetAddrToAddrPort].
	b := ip.As16()

	c.lock.Lock()
	defer c.lock.Unlock()

	var counter *hyperloglog.Sketch
	if c.currentMinute != minuteOfTheDay {
		c.currentMinute = minuteOfTheDay
		counter = hyperloglog.New()
		c.dailyMinuteCounters[minuteOfTheDay] = counter
	} else {
		counter = c.dailyMinuteCounters[minuteOfTheDay]
	}

	counter.Insert(b[:])

	// Only update the hourly and daily counters once per second, since this
	// operation is assumed to take significant amount of time, and so the lock
	// contention should be minimized.  Do that in a separate goroutine to
	// return quicker and not stall the request processing.
	if c.currentUnixSecond != unixSecond {
		c.currentUnixSecond = unixSecond
		go c.update(minuteOfTheDay)
	}
}

// update sets hourly and daily gauges to the estimated values of user counters.
//
// It is expected to be used in a goroutine.
func (c *userCounter) update(m int64) {
	defer log.OnPanic("metrics.userCounter.update")

	hourlyCounter, dailyCounter := hyperloglog.New(), hyperloglog.New()

	c.lock.Lock()
	defer c.lock.Unlock()

	// Go through all minutes in a day while decreasing the current minute m.
	// Decreasing m, as opposed to increasing it or using i as the minute, is
	// required to make summing the hourly statistics within the same loop
	// easier.
	for i := 0; i < dayMinutes; i++ {
		counter := c.dailyMinuteCounters[m]
		m = decrMod(m, dayMinutes)

		if counter == nil {
			continue
		}

		// Use [mustMerge], since the only reason an error may be returned here
		// is when the two sketches do not have the same precisions.
		mustMerge(dailyCounter, counter)

		// Only include the first 60 minutes into the hourly statistics.
		if i < 60 {
			mustMerge(hourlyCounter, counter)
		}
	}

	dnsSvcUsersCount.Set(float64(hourlyCounter.Estimate()))
	dnsSvcUsersDailyCount.Set(float64(dailyCounter.Estimate()))
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
func decrMod(n, m int64) (res int64) {
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
	defaultUserCounter.record(ip)
}
