package rulelist_test

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testReqHost is the request host for tests.
const testReqHost = "blocked.example"

// testRemoteIP is the client IP for tests
var testRemoteIP = netip.MustParseAddr("1.2.3.4")

// testFltListID is the common filter list IDs for tests.
const testFltListID agd.FilterListID = "fl1"

// testBlockRule is the common blocking rule for tests.
const testBlockRule = "||" + testReqHost + "\n"

func TestRefreshable_RulesCount(t *testing.T) {
	rl, err := rulelist.NewFromString(testBlockRule, testFltListID, "", 0, false)
	require.NoError(t, err)

	assert.Equal(t, 1, rl.RulesCount())
}

func TestRefreshable_DNSResult_cache(t *testing.T) {
	rl, err := rulelist.NewFromString(testBlockRule, testFltListID, "", 100, true)
	require.NoError(t, err)

	const qt = dns.TypeA

	t.Run("blocked", func(t *testing.T) {
		dr := rl.DNSResult(testRemoteIP, "", testReqHost, qt, false)
		require.NotNil(t, dr)

		assert.Len(t, dr.NetworkRules, 1)

		cachedDR := rl.DNSResult(testRemoteIP, "", testReqHost, qt, false)
		require.NotNil(t, cachedDR)

		assert.Same(t, dr, cachedDR)
	})

	t.Run("none", func(t *testing.T) {
		const otherHost = "other.example"

		dr := rl.DNSResult(testRemoteIP, "", otherHost, qt, false)
		assert.Nil(t, dr)

		cachedDR := rl.DNSResult(testRemoteIP, "", otherHost, dns.TypeA, false)
		assert.Nil(t, cachedDR)
	})
}

func TestRefreshable_ID(t *testing.T) {
	const svcID = agd.BlockedServiceID("test_service")
	rl, err := rulelist.NewFromString(testBlockRule, testFltListID, svcID, 0, false)
	require.NoError(t, err)

	gotID, gotSvcID := rl.ID()
	assert.Equal(t, testFltListID, gotID)
	assert.Equal(t, svcID, gotSvcID)
}

func TestRefreshable_Refresh(t *testing.T) {
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, testBlockRule, http.StatusOK)
	rl := rulelist.NewRefreshable(
		&internal.RefreshableConfig{
			URL:       srvURL,
			ID:        testFltListID,
			CachePath: cachePath,
			Staleness: filtertest.Staleness,
			MaxSize:   filtertest.FilterMaxSize,
		},
		100,
		true,
	)

	ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
	t.Cleanup(cancel)

	err := rl.Refresh(ctx, false)
	require.NoError(t, err)

	assert.Equal(t, 1, rl.RulesCount())

	dr := rl.DNSResult(testRemoteIP, "", testReqHost, dns.TypeA, false)
	require.NotNil(t, dr)

	assert.Len(t, dr.NetworkRules, 1)
}
