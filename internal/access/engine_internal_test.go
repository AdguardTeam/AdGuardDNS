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
		wg.Add(1)

		host := fmt.Sprintf("%d.%s", i, "block.test")

		go func() {
			defer wg.Done()

			req := dnsservertest.NewReq(host, dns.TypeA, dns.ClassINET)
			assert.True(t, engine.isBlocked(testutil.ContextWithTimeout(t, testTimeout), req))
		}()
	}

	wg.Wait()
}
