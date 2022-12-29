package metrics

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/axiomhq/hyperloglog"
	"github.com/stretchr/testify/assert"
)

func TestUserCounter(t *testing.T) {
	const n = 100_000

	now := time.Now().UTC()
	minuteOfTheDay := int64(now.Hour()*60 + now.Minute())

	// Use a constant seed to make the test reproducible.
	src := rand.NewSource(1234)
	r := rand.New(src)
	ip := randIP(r)

	c := newUserCounter()
	for i := 0; i < n; i++ {
		c.record(ip)
		ip = randIP(r)
	}

	// Use the next minute as a starting point, since it could change during the
	// test run.
	m := minuteOfTheDay + 1
	hourlyCounter := hyperloglog.New()
	for i := 0; i < 60; i++ {
		counter := c.dailyMinuteCounters[m]
		m = decrMod(m, dayMinutes)

		if counter != nil {
			mustMerge(hourlyCounter, counter)
		}
	}

	assert.InEpsilon(t, uint64(n), hourlyCounter.Estimate(), 0.01)
}

// randIP returns a pseudorandomly generated IP address.
func randIP(r *rand.Rand) (ip netip.Addr) {
	return netip.AddrFrom4([4]byte{
		byte(r.Int31n(256)),
		byte(r.Int31n(256)),
		byte(r.Int31n(256)),
		byte(r.Int31n(256)),
	})
}
