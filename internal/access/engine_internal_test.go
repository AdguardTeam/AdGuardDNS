package access

import (
	"fmt"
	"sync"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestBlockedHostEngine_IsBlocked(t *testing.T) {
	t.Parallel()

	rules := []string{
		"block.test",
		"UPPERCASE.test",
		"||block_aaaa.test^$dnstype=AAAA",
		"||allowlist.test^",
		"@@||allow.allowlist.test^",
	}

	engine := newBlockedHostEngine(rules)

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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := dnsservertest.NewReq(tc.host, tc.qt, dns.ClassINET)

			blocked := engine.isBlocked(req)
			tc.want(t, blocked)
		})
	}
}

func TestBlockedHostEngine_IsBlocked_concurrent(t *testing.T) {
	const routinesLimit = 50

	rules := []string{"||block.test^"}
	engine := newBlockedHostEngine(rules)

	wg := &sync.WaitGroup{}
	for i := 0; i < routinesLimit; i++ {
		wg.Add(1)

		host := fmt.Sprintf("%d.%s", i, "block.test")

		go func() {
			defer wg.Done()

			req := dnsservertest.NewReq(host, dns.TypeA, dns.ClassINET)
			assert.True(t, engine.isBlocked(req))
		}()
	}

	wg.Wait()
}
