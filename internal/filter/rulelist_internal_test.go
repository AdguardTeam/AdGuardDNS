package filter

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleListFilter_dnsResult_cache(t *testing.T) {
	rl, err := newRuleListFltFromStr("||example.com^", "fl1", "", 100, true)
	require.NoError(t, err)

	t.Run("blocked", func(t *testing.T) {
		dr := rl.dnsResult(testRemoteIP, "", testReqHost, dns.TypeA, false)
		require.NotNil(t, dr)

		assert.Len(t, dr.NetworkRules, 1)

		cachedDR := rl.dnsResult(testRemoteIP, "", testReqHost, dns.TypeA, false)
		require.NotNil(t, cachedDR)

		assert.Same(t, dr, cachedDR)
	})

	t.Run("none", func(t *testing.T) {
		const otherHost = "other.example"

		dr := rl.dnsResult(testRemoteIP, "", otherHost, dns.TypeA, false)
		assert.Nil(t, dr)

		cachedDR := rl.dnsResult(testRemoteIP, "", otherHost, dns.TypeA, false)
		assert.Nil(t, cachedDR)
	})
}
