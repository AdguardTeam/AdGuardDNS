package metrics_test

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Use the same seed to make the test reproducible.
var randSeed = [32]byte([]byte("01234567890123456789012345678901"))

// Gauges for tests.
var (
	testLastHour = prometheus.NewGauge(prometheus.GaugeOpts{})
	testLastDay  = prometheus.NewGauge(prometheus.GaugeOpts{})
)

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// randIPBytes is a test helper that returns a pseudorandomly generated
// IP-address bytes.  fam must be either [netutil.AddrFamilyIPv4] or
// [netutil.AddrFamilyIPv6].
func randIPBytes(t testing.TB, src *rand.ChaCha8, fam netutil.AddrFamily) (ipBytes []byte) {
	t.Helper()

	switch fam {
	case netutil.AddrFamilyIPv4:
		ipBytes = make([]byte, net.IPv4len)
	case netutil.AddrFamilyIPv6:
		ipBytes = make([]byte, net.IPv6len)
	default:
		t.Fatalf("unexpected address family %q", fam)
	}

	n, err := src.Read(ipBytes)
	require.NoError(t, err)
	require.Equal(t, len(ipBytes), n)

	return ipBytes
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
			src := rand.NewChaCha8(randSeed)
			c := metrics.NewUserCounter(testLogger, testLastHour, testLastDay)

			ctx := context.Background()
			for _, now := range tc.nows {
				c.Record(ctx, now, randIPBytes(t, src, netutil.AddrFamilyIPv6), true)
			}

			hourly, daily := c.Estimate()
			assert.Equal(t, tc.wantHourly, hourly)
			assert.Equal(t, tc.wantDaily, daily)
		})
	}
}

func TestUserCounter_simple(t *testing.T) {
	const ipsPerMinute = 2

	src := rand.NewChaCha8(randSeed)

	c := metrics.NewUserCounter(testLogger, testLastHour, testLastDay)

	now := time.Unix(0, 0).UTC()
	for d, h := now.Day(), now.Hour(); now.Day() == d; h = now.Hour() {
		t.Run(strconv.Itoa(now.Hour()), func(t *testing.T) {
			ctx := context.Background()
			for ; now.Hour() == h; now = now.Add(1 * time.Minute) {
				for range ipsPerMinute {
					c.Record(ctx, now, randIPBytes(t, src, netutil.AddrFamilyIPv4), true)
				}
			}

			hourly, _ := c.Estimate()
			assert.InEpsilon(t, uint64(ipsPerMinute*60), hourly, 0.02)
		})
	}

	_, daily := c.Estimate()
	assert.InEpsilon(t, uint64(ipsPerMinute*24*60), daily, 0.02)
}

func BenchmarkUserCounter_Estimate(b *testing.B) {
	const n = 100

	ctx := context.Background()
	zeroTime := time.Unix(0, 0).UTC()

	sparseCounter := metrics.NewUserCounter(testLogger, testLastHour, testLastDay)
	for d, now := zeroTime.Day(), zeroTime; d == now.Day(); now = now.Add(time.Minute) {
		src := rand.NewChaCha8(randSeed)
		for range n {
			sparseCounter.Record(ctx, now, randIPBytes(b, src, netutil.AddrFamilyIPv6), true)
		}
	}

	seqCounter := metrics.NewUserCounter(testLogger, testLastHour, testLastDay)
	for d, now := zeroTime.Day(), zeroTime; d == now.Day(); now = now.Add(time.Minute) {
		addr := netip.AddrFrom16([16]byte{})
		for range n {
			addr = addr.Next()
			addrArr := addr.As16()
			seqCounter.Record(ctx, now, addrArr[:], true)
		}
	}

	b.Run("sparse", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = sparseCounter.Estimate()
		}
	})

	b.Run("sequential", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = seqCounter.Estimate()
		}
	})

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/metrics
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkUserCounter_Estimate/sparse-12         	   17648	     68332 ns/op	   10384 B/op	      38 allocs/op
	// BenchmarkUserCounter_Estimate/sequential-12     	   17542	     68500 ns/op	   10384 B/op	      38 allocs/op
}
