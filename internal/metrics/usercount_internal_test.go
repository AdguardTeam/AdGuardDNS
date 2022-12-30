package metrics

import (
	"math/rand"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserCounter(t *testing.T) {
	const ipsPerMinute = 2

	// Use a constant seed to make the test reproducible.
	src := rand.NewSource(1234)
	r := rand.New(src)

	c := newUserCounter()

	now := time.Unix(0, 0).UTC()
	for h := 0; h < 24; h++ {
		t.Run(strconv.Itoa(h), func(t *testing.T) {
			for m := 0; m < 60; m++ {
				for i := 0; i < ipsPerMinute; i++ {
					c.record(now, randIP(r), true)
				}

				now = now.Add(1 * time.Minute)
			}

			hourly, _ := c.estimate(h*60 + 59)
			assert.InEpsilon(t, uint64(ipsPerMinute*60), hourly, 0.02)
		})
	}

	_, daily := c.estimate(23*60 + 59)
	assert.InEpsilon(t, uint64(ipsPerMinute*24*60), daily, 0.02)
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
