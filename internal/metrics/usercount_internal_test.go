package metrics

import (
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Use a constant seed to make the test reproducible.
const randSeed = 1234

// randIP is a test helper that returns a pseudorandomly generated IP address.
// fam must be either [netutil.AddrFamilyIPv4] or [netutil.AddrFamilyIPv6].
func randIP(t testing.TB, r *rand.Rand, fam netutil.AddrFamily) (ip netip.Addr) {
	t.Helper()

	var buf []byte
	switch fam {
	case netutil.AddrFamilyIPv4:
		buf = make([]byte, net.IPv4len)
	case netutil.AddrFamilyIPv6:
		buf = make([]byte, net.IPv6len)
	default:
		t.Fatalf("unexpected address family %q", fam)
	}

	n, err := r.Read(buf)
	require.NoError(t, err)
	require.Equal(t, len(buf), n)

	var ok bool
	ip, ok = netip.AddrFromSlice(buf)
	require.True(t, ok)

	return ip
}

func TestUserCounter_Estimate(t *testing.T) {
	// TODO(e.burkov):  Add tests for more than 48 hours gaps, when it will be
	// supported.
	testCases := []struct {
		name       string
		nows       []time.Time
		wantDaily  uint64
		wantHourly uint64
	}{{
		name:       "empty",
		nows:       nil,
		wantDaily:  0,
		wantHourly: 0,
	}, {
		name: "each_minute",
		nows: []time.Time{
			time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 1, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 2, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 3, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 4, 0, 0, time.UTC),
		},
		wantDaily:  4,
		wantHourly: 4,
	}, {
		name: "each_hour",
		nows: []time.Time{
			time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 1, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 2, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 3, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 4, 0, 0, 0, time.UTC),
		},
		wantDaily:  4,
		wantHourly: 1,
	}, {
		name: "each_day",
		nows: []time.Time{
			time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 3, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 4, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 5, 0, 0, 0, 0, time.UTC),
		},
		wantDaily:  0,
		wantHourly: 0,
	}, {
		name: "few_per_minute",
		nows: []time.Time{
			time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 0, 1, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 0, 2, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 0, 3, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 1, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 1, 1, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 1, 2, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 1, 3, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 2, 0, 0, time.UTC),
		},
		wantDaily:  8,
		wantHourly: 8,
	}, {
		name: "few_per_hour",
		nows: []time.Time{
			time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 1, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 2, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 3, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 1, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 1, 1, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 1, 2, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 1, 3, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 2, 0, 0, 0, time.UTC),
		},
		wantDaily:  8,
		wantHourly: 4,
	}, {
		name: "few_hours_gap",
		nows: []time.Time{
			time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 1, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 2, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 4, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 4, 1, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 4, 2, 0, 0, time.UTC),
		},
		wantDaily:  5,
		wantHourly: 3,
	}, {
		name: "few_per_day",
		nows: []time.Time{
			time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 1, 0, 0, time.UTC),
			time.Date(2023, 1, 1, 0, 2, 0, 0, time.UTC),
			time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 2, 0, 1, 0, 0, time.UTC),
			time.Date(2023, 1, 2, 0, 2, 0, 0, time.UTC),
		},
		wantDaily:  5,
		wantHourly: 3,
	}, {
		name: "day_and_hour_gap",
		nows: []time.Time{
			time.Date(2023, 1, 1, 23, 0, 0, 0, time.UTC),
			time.Date(2023, 1, 3, 0, 0, 0, 0, time.UTC),
		},
		wantDaily:  1,
		wantHourly: 1,
	}, {
		name: "day_and_minute_gap",
		nows: []time.Time{
			time.Date(2023, 1, 1, 23, 59, 0, 0, time.UTC),
			time.Date(2023, 1, 3, 0, 0, 0, 0, time.UTC),
		},
		wantDaily:  1,
		wantHourly: 1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := rand.New(rand.NewSource(randSeed))
			c := newUserCounter()

			for _, now := range tc.nows {
				c.record(now, randIP(t, r, netutil.AddrFamilyIPv6), true)
			}

			hourly, daily := c.estimate()
			assert.Equal(t, tc.wantHourly, hourly)
			assert.Equal(t, tc.wantDaily, daily)
		})
	}
}

func TestUserCounter_simple(t *testing.T) {
	const ipsPerMinute = 2

	src := rand.NewSource(randSeed)
	r := rand.New(src)

	c := newUserCounter()

	now := time.Unix(0, 0).UTC()
	for d, h := now.Day(), now.Hour(); now.Day() == d; h = now.Hour() {
		t.Run(strconv.Itoa(now.Hour()), func(t *testing.T) {
			for ; now.Hour() == h; now = now.Add(1 * time.Minute) {
				for range ipsPerMinute {
					c.record(now, randIP(t, r, netutil.AddrFamilyIPv4), true)
				}
			}

			hourly, _ := c.estimate()
			assert.InEpsilon(t, uint64(ipsPerMinute*60), hourly, 0.02)
		})
	}

	_, daily := c.estimate()
	assert.InEpsilon(t, uint64(ipsPerMinute*24*60), daily, 0.02)
}

// uint64Sink is a sink for uint64 values returned from benchmarks.
var uint64Sink uint64

func BenchmarkUserCounter_Estimate(b *testing.B) {
	const n = 100

	zeroTime := time.Unix(0, 0).UTC()

	sparseCounter := newUserCounter()
	for d, now := zeroTime.Day(), zeroTime; d == now.Day(); now = now.Add(time.Minute) {
		r := rand.New(rand.NewSource(randSeed))
		for range n {
			sparseCounter.record(now, randIP(b, r, netutil.AddrFamilyIPv6), true)
		}
	}

	seqCounter := newUserCounter()
	for d, now := zeroTime.Day(), zeroTime; d == now.Day(); now = now.Add(time.Minute) {
		addr := netip.AddrFrom16([16]byte{})
		for range n {
			addr = addr.Next()
			seqCounter.record(now, addr, true)
		}
	}

	b.Run("sparse", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			uint64Sink, uint64Sink = sparseCounter.estimate()
		}
	})

	b.Run("sequential", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			uint64Sink, uint64Sink = seqCounter.estimate()
		}
	})
}
