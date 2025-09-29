package access

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

func TestBlockedHostEngine_IsBlocked(t *testing.T) {
	t.Parallel()

	rules := []string{
		"block.test",
		"UPPERCASE.test",
		"||block_aaaa.test^$dnstype=AAAA",
		"||allowlist.test^",
		"@@||allow.allowlist.test^",
	}

	engine := newBlockedHostEngine(EmptyProfileMetrics{}, rules)

	testCases := []struct {
		want assert.BoolAssertionFunc
		name string
		host string
		qt   uint16
	}{{
		want: assert.False,
		name: "pass",
		host: "pass.test",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "blocked_domain_A",
		host: "block.test",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "blocked_domain_HTTPS",
		host: "block.test",
		qt:   dns.TypeHTTPS,
	}, {
		want: assert.True,
		name: "uppercase_domain",
		host: "uppercase.test",
		qt:   dns.TypeHTTPS,
	}, {
		want: assert.False,
		name: "pass_qt",
		host: "block_aaaa.test",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "block_qt",
		host: "block_aaaa.test",
		qt:   dns.TypeAAAA,
	}, {
		want: assert.True,
		name: "allowlist_block",
		host: "block.allowlist.test",
		qt:   dns.TypeA,
	}, {
		want: assert.False,
		name: "allowlist_test",
		host: "allow.allowlist.test",
		qt:   dns.TypeA,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := dnsservertest.NewReq(tc.host, tc.qt, dns.ClassINET)

			blocked := engine.isBlocked(testutil.ContextWithTimeout(t, testTimeout), req)
			tc.want(t, blocked)
		})
	}
}

func TestBlockedHostEngine_IsBlocked_concurrent(t *testing.T) {
	const routinesLimit = 50

	rules := []string{"||block.test^"}
	engine := newBlockedHostEngine(EmptyProfileMetrics{}, rules)

	wg := &sync.WaitGroup{}
	for i := range routinesLimit {
		host := fmt.Sprintf("%d.%s", i, "block.test")

		wg.Go(func() {
			req := dnsservertest.NewReq(host, dns.TypeA, dns.ClassINET)
			assert.True(t, engine.isBlocked(testutil.ContextWithTimeout(t, testTimeout), req))
		})
	}

	wg.Wait()
}

func BenchmarkBlockedHostEngine_IsBlocked(b *testing.B) {
	engine := newBlockedHostEngine(EmptyProfileMetrics{}, []string{
		"block.test",
	})

	ctx := testutil.ContextWithTimeout(b, testTimeout)

	b.Run("pass", func(b *testing.B) {
		req := dnsservertest.NewReq("pass.test", dns.TypeA, dns.ClassINET)

		// Warmup to fill the pools and the slices.
		blocked := engine.isBlocked(ctx, req)
		require.False(b, blocked)

		b.ReportAllocs()
		for b.Loop() {
			blocked = engine.isBlocked(ctx, req)
		}

		require.False(b, blocked)
	})

	b.Run("block", func(b *testing.B) {
		req := dnsservertest.NewReq("block.test", dns.TypeA, dns.ClassINET)

		// Warmup to fill the pools and the slices.
		blocked := engine.isBlocked(ctx, req)
		require.True(b, blocked)

		b.ReportAllocs()
		for b.Loop() {
			blocked = engine.isBlocked(ctx, req)
		}

		require.True(b, blocked)
	})

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/access
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkBlockedHostEngine_IsBlocked/pass-16         	 3750295	       317.8 ns/op	      16 B/op	       1 allocs/op
	//	BenchmarkBlockedHostEngine_IsBlocked/block-16        	 3407104	       350.2 ns/op	      24 B/op	       1 allocs/op
}
