package access_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testAccessMtrc is the common profile access engine metrics for tests.
var testAccessMtrc = access.EmptyProfileMetrics{}

func TestGlobal_IsBlockedHost(t *testing.T) {
	global, err := access.NewGlobal([]string{
		"block.test",
		"UPPERCASE.test",
		"||block_aaaa.test^$dnstype=AAAA",
		"||allowlist.test^",
		"@@||allow.allowlist.test^",
	}, nil)
	require.NoError(t, err)

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
			blocked := global.IsBlockedHost(tc.host, tc.qt)
			tc.want(t, blocked)
		})
	}
}

func TestGlobal_IsBlockedIP(t *testing.T) {
	global, err := access.NewGlobal([]string{}, []netip.Prefix{
		netip.MustParsePrefix("1.1.1.1/32"),
		netip.MustParsePrefix("2.2.2.0/8"),
	})
	require.NoError(t, err)

	testCases := []struct {
		want assert.BoolAssertionFunc
		ip   netip.Addr
		name string
	}{{
		want: assert.False,
		name: "pass",
		ip:   netip.MustParseAddr("1.1.1.0"),
	}, {
		want: assert.True,
		name: "block_ip",
		ip:   netip.MustParseAddr("1.1.1.1"),
	}, {
		want: assert.False,
		name: "pass_subnet",
		ip:   netip.MustParseAddr("1.2.2.2"),
	}, {
		want: assert.True,
		name: "block_subnet",
		ip:   netip.MustParseAddr("2.2.2.2"),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blocked := global.IsBlockedIP(tc.ip)
			tc.want(t, blocked)
		})
	}
}
