package filterstorage_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterstorage"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// unit is a convenient alias for struct{}.
type unit = struct{}

// Common filtering results.
var (
	resultAdult = &filter.ResultModifiedRequest{
		Msg:  dnsservertest.NewReq(filtertest.FQDNAdultContentRepl, dns.TypeA, dns.ClassINET),
		List: filter.IDAdultBlocking,
		Rule: filter.RuleText(filtertest.HostAdultContent),
	}

	resultBlockedSvc = &filter.ResultBlocked{
		List: filter.IDBlockedService,
		Rule: filter.RuleText(filtertest.BlockedServiceID1),
	}

	resultDanger = &filter.ResultModifiedRequest{
		Msg:  dnsservertest.NewReq(filtertest.FQDNDangerousRepl, dns.TypeA, dns.ClassINET),
		List: filter.IDSafeBrowsing,
		Rule: filter.RuleText(filtertest.HostDangerous),
	}

	resultNewReg = &filter.ResultModifiedRequest{
		Msg:  dnsservertest.NewReq(filtertest.FQDNNewlyRegisteredRepl, dns.TypeA, dns.ClassINET),
		List: filter.IDNewRegDomains,
		Rule: filter.RuleText(filtertest.HostNewlyRegistered),
	}

	resultRuleList = &filter.ResultBlocked{
		List: filtertest.RuleListID1,
		Rule: filtertest.RuleBlock,
	}

	resultSafeSearchGen = &filter.ResultModifiedRequest{
		Msg:  dnsservertest.NewReq(filtertest.FQDNSafeSearchGeneralRepl, dns.TypeA, dns.ClassINET),
		List: filter.IDGeneralSafeSearch,
		Rule: filter.RuleText(filtertest.HostSafeSearchGeneral),
	}

	resultSafeSearchYT = &filter.ResultModifiedRequest{
		Msg:  dnsservertest.NewReq(filtertest.FQDNSafeSearchYouTubeRepl, dns.TypeA, dns.ClassINET),
		List: filter.IDYoutubeSafeSearch,
		Rule: filter.RuleText(filtertest.HostSafeSearchYouTube),
	}
)

// newDefault returns a fully ready and initially refreshed
// [*filterstorage.Default] for tests.  It has the following filters:
//
//   - A rule-list index with one filter with ID [filtertest.RuleListID1] and a
//     rule to block [filtertest.HostBlocked].
//   - Safe-search filters, both general and YouTube, with rules for
//     [filtertest.HostSafeSearchGeneral] and
//     [filtertest.HostSafeSearchYouTube].
//   - A blocked-service index with one service with ID
//     [filtertest.BlockedServiceID1] blocking [filtertest.HostBlockedService1].
//   - All hash-prefix filters, which block [filtertest.HostAdultContent],
//     [filtertest.HostDangerous], and [filtertest.HostNewlyRegistered].
func newDefault(tb testing.TB) (s *filterstorage.Default) {
	const (
		blockData = filtertest.RuleBlockStr + "\n"
		ssGenData = filtertest.RuleSafeSearchGeneralHostStr + "\n"
		ssYTData  = filtertest.RuleSafeSearchYouTubeStr + "\n"
	)

	rlCh := make(chan unit, 1)
	_, ruleListURL := filtertest.PrepareRefreshable(tb, rlCh, blockData, http.StatusOK)
	rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())

	rlIdxCh := make(chan unit, 1)
	_, ruleListIdxURL := filtertest.PrepareRefreshable(
		tb,
		rlIdxCh,
		string(rlIdxData),
		http.StatusOK,
	)

	ssGenCh, ssYTCh := make(chan unit, 1), make(chan unit, 1)
	_, safeSearchGenURL := filtertest.PrepareRefreshable(tb, ssGenCh, ssGenData, http.StatusOK)
	_, safeSearchYTURL := filtertest.PrepareRefreshable(tb, ssYTCh, ssYTData, http.StatusOK)

	svcIdxCh := make(chan unit, 1)
	_, svcIdxURL := filtertest.PrepareRefreshable(
		tb,
		svcIdxCh,
		filtertest.BlockedServiceIndex,
		http.StatusOK,
	)

	c := newDisabledConfig(tb, newConfigRuleLists(ruleListIdxURL))
	c.BlockedServices = newConfigBlockedServices(svcIdxURL)
	c.HashPrefix = &filterstorage.HashPrefixConfig{
		Adult:           filtertest.NewHashprefixFilter(tb, filter.IDAdultBlocking),
		Dangerous:       filtertest.NewHashprefixFilter(tb, filter.IDSafeBrowsing),
		NewlyRegistered: filtertest.NewHashprefixFilter(tb, filter.IDNewRegDomains),
	}
	c.SafeSearchGeneral = newConfigSafeSearch(safeSearchGenURL, filter.IDGeneralSafeSearch)
	c.SafeSearchYouTube = newConfigSafeSearch(safeSearchYTURL, filter.IDYoutubeSafeSearch)

	s, err := filterstorage.New(c)
	require.NoError(tb, err)

	// initialTimeout is the maximum time to wait for a filter storage
	// initialization.  A separate timeout is used to make the tests using this
	// helper pass on older, slower machines.
	const initialTimeout = 2 * filtertest.Timeout

	ctx := testutil.ContextWithTimeout(tb, initialTimeout)
	err = s.RefreshInitial(ctx)
	require.NoError(tb, err)

	testutil.RequireReceive(tb, rlCh, filtertest.Timeout)
	testutil.RequireReceive(tb, rlIdxCh, filtertest.Timeout)
	testutil.RequireReceive(tb, ssGenCh, filtertest.Timeout)
	testutil.RequireReceive(tb, ssYTCh, filtertest.Timeout)
	testutil.RequireReceive(tb, svcIdxCh, filtertest.Timeout)

	return s
}

// newDisabledConfig returns a new [*filterstorage.Config] with fields related
// to filters set to disabled (if possible) and others, to the default test
// entities.
func newDisabledConfig(
	tb testing.TB,
	rlConf *filterstorage.RuleListsConfig,
) (c *filterstorage.Config) {
	tb.Helper()

	return &filterstorage.Config{
		BaseLogger: slogutil.NewDiscardLogger(),
		Logger:     slogutil.NewDiscardLogger(),
		BlockedServices: &filterstorage.BlockedServicesConfig{
			Enabled: false,
		},
		Custom: &filterstorage.CustomConfig{
			CacheCount: filtertest.CacheCount,
		},
		HashPrefix: &filterstorage.HashPrefixConfig{},
		RuleLists:  rlConf,
		SafeSearchGeneral: &filterstorage.SafeSearchConfig{
			ID:      filter.IDGeneralSafeSearch,
			Enabled: false,
		},
		SafeSearchYouTube: &filterstorage.SafeSearchConfig{
			ID:      filter.IDYoutubeSafeSearch,
			Enabled: false,
		},
		CacheManager: agdcache.EmptyManager{},
		Clock:        timeutil.SystemClock{},
		ErrColl:      agdtest.NewErrorCollector(),
		Metrics:      filter.EmptyMetrics{},
		CacheDir:     tb.TempDir(),
	}
}

// newConfigBlockedServices is a test helper that returns a new enabled
// *ConfigBlockedServices with the given index URL.  The rest of the fields are
// set to the corresponding [filtertest] values.
func newConfigBlockedServices(indexURL *url.URL) (c *filterstorage.BlockedServicesConfig) {
	return &filterstorage.BlockedServicesConfig{
		IndexURL:            indexURL,
		IndexMaxSize:        filtertest.FilterMaxSize,
		IndexRefreshTimeout: filtertest.Timeout,
		IndexStaleness:      filtertest.Staleness,
		ResultCacheCount:    filtertest.CacheCount,
		ResultCacheEnabled:  true,
		Enabled:             true,
	}
}

// newConfigRuleLists is a test helper that returns a new *ConfigRuleLists with
// the given index URL.  The rest of the fields are set to the corresponding
// [filtertest] values.
func newConfigRuleLists(indexURL *url.URL) (c *filterstorage.RuleListsConfig) {
	return &filterstorage.RuleListsConfig{
		IndexURL:            indexURL,
		IndexMaxSize:        filtertest.FilterMaxSize,
		MaxSize:             filtertest.FilterMaxSize,
		IndexRefreshTimeout: filtertest.Timeout,
		IndexStaleness:      filtertest.Staleness,
		RefreshTimeout:      filtertest.Timeout,
		Staleness:           filtertest.Staleness,
		ResultCacheCount:    filtertest.CacheCount,
		ResultCacheEnabled:  true,
	}
}

// newConfigSafeSearch is a test helper that returns a new enabled
// *ConfigSafeSearch with the given filter URL and ID.  The rest of the fields
// are set to the corresponding [filtertest] values.
func newConfigSafeSearch(u *url.URL, id filter.ID) (c *filterstorage.SafeSearchConfig) {
	return &filterstorage.SafeSearchConfig{
		URL:              u,
		ID:               id,
		MaxSize:          filtertest.FilterMaxSize,
		ResultCacheTTL:   filtertest.CacheTTL,
		RefreshTimeout:   filtertest.Timeout,
		Staleness:        filtertest.Staleness,
		ResultCacheCount: filtertest.CacheCount,
		Enabled:          true,
	}
}
