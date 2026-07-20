package filterstorage_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterstorage"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/ruleliststorage"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	indexURL := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "index.example",
	}

	servicesDisabled := &filterstorage.BlockedServicesConfig{
		Enabled: false,
	}

	safeSearchGeneralDisabled := &filterstorage.SafeSearchConfig{
		ID:      filter.IDGeneralSafeSearch,
		Enabled: false,
	}

	safeSearchYouTubeDisabled := &filterstorage.SafeSearchConfig{
		ID:      filter.IDYoutubeSafeSearch,
		Enabled: false,
	}

	testCases := []struct {
		services      *filterstorage.BlockedServicesConfig
		safeSearchGen *filterstorage.SafeSearchConfig
		safeSearchYT  *filterstorage.SafeSearchConfig
		name          string
	}{{
		services:      servicesDisabled,
		safeSearchGen: safeSearchGeneralDisabled,
		safeSearchYT:  safeSearchYouTubeDisabled,
		name:          "empty",
	}, {
		services:      newConfigBlockedServices(indexURL),
		safeSearchGen: safeSearchGeneralDisabled,
		safeSearchYT:  safeSearchYouTubeDisabled,
		name:          "blocked_services",
	}, {
		services:      servicesDisabled,
		safeSearchGen: newConfigSafeSearch(indexURL, filter.IDGeneralSafeSearch),
		safeSearchYT:  safeSearchYouTubeDisabled,
		name:          "safe_search_general",
	}, {
		services:      servicesDisabled,
		safeSearchGen: safeSearchGeneralDisabled,
		safeSearchYT:  newConfigSafeSearch(indexURL, filter.IDYoutubeSafeSearch),
		name:          "safe_search_youtube",
	}}

	rlStorage, sErr := ruleliststorage.New(&ruleliststorage.Config{
		BaseLogger:         filtertest.Logger,
		CacheManager:       agdcache.EmptyManager{},
		Clock:              timeutil.SystemClock{},
		ErrColl:            agdtest.NewErrorCollector(),
		IndexStorage:       filterindex.EmptyRulelistStorage{},
		Logger:             filtertest.Logger,
		Metrics:            filter.EmptyMetrics{},
		CacheDir:           t.TempDir(),
		MaxSize:            filtertest.FilterMaxSize,
		RefreshTimeout:     filtertest.Timeout,
		Staleness:          filtertest.Staleness,
		ResultCacheCount:   filtertest.CacheCount,
		ResultCacheEnabled: true,
	})
	require.NoError(t, sErr)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := newDisabledConfig(t, rlStorage, newIndexConfig(indexURL))
			c.BlockedServices = tc.services
			c.SafeSearchGeneral = tc.safeSearchGen
			c.SafeSearchYouTube = tc.safeSearchYT

			s, err := filterstorage.New(c)
			assert.NotNil(t, s)
			assert.NoError(t, err)
		})
	}
}

func TestDefault_ForConfig_nil(t *testing.T) {
	t.Parallel()

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	s := newDefault(t)
	f := s.ForConfig(ctx, nil)
	require.NotNil(t, f)

	assert.IsType(t, filter.Empty{}, f)
}

func TestDefault_ForConfig_client(t *testing.T) {
	t.Parallel()

	s := newDefault(t)

	require.True(t, t.Run("custom", func(t *testing.T) {
		conf := newFltConfigCli(
			newFltConfigParental(false, false, false, false),
			newFltConfigRuleList(false),
			newFltConfigSafeBrowsing(false, false, false, false),
		)

		conf.CustomFilter.Enabled = true
		conf.CustomFilter.Filter = custom.New(&custom.Config{
			Logger: filtertest.Logger,
			Rules:  []filter.RuleText{filtertest.RuleBlock},
		})

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		f := s.ForConfig(ctx, conf)
		require.NotNil(t, f)

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		r, err := f.FilterRequest(ctx, filtertest.NewARequest(t, filtertest.HostBlocked))
		require.NoError(t, err)

		wantRes := &filter.ResultBlocked{
			List: filter.IDCustom,
			Rule: filtertest.RuleBlock,
		}

		filtertest.AssertEqualResult(t, wantRes, r)
	}))

	require.True(t, t.Run("schedule", func(t *testing.T) {
		conf := newFltConfigCli(
			newFltConfigParental(false, true, false, false),
			newFltConfigRuleList(false),
			newFltConfigSafeBrowsing(false, false, false, false),
		)

		now := time.Now()

		week := &[7]filter.DayIntervals{}
		week[now.Weekday()] = filter.DayIntervals{
			{Start: 0, End: filter.MaxDayIntervalEndMinutes},
		}

		conf.Parental.PauseSchedule = &filter.ConfigSchedule{
			Week:     (*filter.WeeklySchedule)(week),
			TimeZone: agdtime.UTC(),
		}

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		f := s.ForConfig(ctx, conf)
		require.NotNil(t, f)

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		r, err := f.FilterRequest(ctx, filtertest.NewARequest(t, filtertest.HostAdultContent))
		require.NoError(t, err)

		assert.Nil(t, r)
	}))
}

func TestDefault_ForConfig_common(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		parental     *filter.ConfigParental
		ruleList     *filter.ConfigRuleList
		safeBrowsing *filter.ConfigSafeBrowsing
		name         string
	}{{
		parental:     newFltConfigParental(false, false, false, false),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(false, false, false, false),
		name:         "empty",
	}, {
		parental:     newFltConfigParental(true, false, false, false),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(false, false, false, false),
		name:         "adult_content",
	}, {
		parental:     newFltConfigParental(false, true, false, false),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(false, false, false, false),
		name:         "blocked_service",
	}, {
		parental:     newFltConfigParental(false, false, false, false),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(true, false, false, false),
		name:         "dangerous",
	}, {
		parental:     newFltConfigParental(false, false, false, false),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(false, true, false, false),
		name:         "newly_registered",
	}, {
		parental:     newFltConfigParental(false, false, false, false),
		ruleList:     newFltConfigRuleList(true),
		safeBrowsing: newFltConfigSafeBrowsing(false, false, false, false),
		name:         "rule_list_blocked",
	}, {
		parental:     newFltConfigParental(false, false, true, false),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(false, false, false, false),
		name:         "safe_search_general",
	}, {
		parental:     newFltConfigParental(false, false, false, true),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(false, false, false, false),
		name:         "safe_search_youtube",
	}, {
		parental:     newFltConfigParental(false, false, false, false),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(false, false, true, false),
		name:         "safe_browsing_typosquatting",
	}, {
		parental:     newFltConfigParental(false, false, false, false),
		ruleList:     newFltConfigRuleList(false),
		safeBrowsing: newFltConfigSafeBrowsing(false, false, false, true),
		name:         "safe_browsing_homoglyph",
	}, {
		parental:     newFltConfigParental(true, true, true, true),
		ruleList:     newFltConfigRuleList(true),
		safeBrowsing: newFltConfigSafeBrowsing(true, true, true, true),
		name:         "all",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newDefault(t)

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			cliFlt := s.ForConfig(ctx, newFltConfigCli(tc.parental, tc.ruleList, tc.safeBrowsing))
			require.NotNil(t, cliFlt)

			ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
			grpFlt := s.ForConfig(ctx, &filter.ConfigGroup{
				Parental:     tc.parental,
				RuleList:     tc.ruleList,
				SafeBrowsing: tc.safeBrowsing,
			})
			require.NotNil(t, grpFlt)

			t.Run("client", func(t *testing.T) {
				assertFilterResults(t, cliFlt, tc.parental, tc.ruleList, tc.safeBrowsing)
			})

			t.Run("group", func(t *testing.T) {
				assertFilterResults(t, grpFlt, tc.parental, tc.ruleList, tc.safeBrowsing)
			})
		})
	}
}

// newFltConfigParental returns a *filter.FilterConfigParental with the
// features properly enabled or disabled.
func newFltConfigParental(hpAdult, svc, ssGen, ssYT bool) (c *filter.ConfigParental) {
	c = &filter.ConfigParental{
		Categories:               &filter.ConfigCategories{},
		Enabled:                  svc || hpAdult || ssGen || ssYT,
		AdultBlockingEnabled:     hpAdult,
		SafeSearchGeneralEnabled: ssGen,
		SafeSearchYouTubeEnabled: ssYT,
	}

	if svc {
		c.BlockedServices = []filter.BlockedServiceID{
			filtertest.BlockedServiceID1,
		}
	}

	return c
}

// newFltConfigRuleList returns a *filter.FilterConfigRuleList that is
// either enabled with one rule-list filter or is disabled.
func newFltConfigRuleList(enabled bool) (c *filter.ConfigRuleList) {
	c = &filter.ConfigRuleList{
		Enabled: enabled,
	}

	if enabled {
		c.IDs = []filter.ID{
			filtertest.RuleListID1,
		}
	}

	return c
}

// newFltConfigSafeBrowsing returns a *filter.FilterConfigSafeBrowsing
// with the features properly enabled or disabled.
func newFltConfigSafeBrowsing(
	hpDanger bool,
	hpNew bool,
	typosquatting bool,
	homoglyph bool,
) (c *filter.ConfigSafeBrowsing) {
	return &filter.ConfigSafeBrowsing{
		Homoglyph: &filter.ConfigHomoglyph{
			Enabled: homoglyph,
		},
		Typosquatting: &filter.ConfigTyposquatting{
			Enabled: typosquatting,
		},
		Enabled:                       hpDanger || hpNew || typosquatting || homoglyph,
		DangerousDomainsEnabled:       hpDanger,
		NewlyRegisteredDomainsEnabled: hpNew,
	}
}

// newFltConfigCli returns a *filter.FilterConfigClient with the given
// configs as well as the additional necessary for a client's filter
// configuration.
func newFltConfigCli(
	pConf *filter.ConfigParental,
	rlConf *filter.ConfigRuleList,
	sbConf *filter.ConfigSafeBrowsing,
) (c *filter.ConfigClient) {
	return &filter.ConfigClient{
		CustomFilter:   &filter.ConfigCustomFilter{},
		CustomRuleList: &filter.ConfigCustomRuleList{},
		Parental:       pConf,
		RuleList:       rlConf,
		SafeBrowsing:   sbConf,
	}
}

// assertFilterResults is a test helper for asserting a filter's results based
// on the configuration.
func assertFilterResults(
	tb testing.TB,
	flt filter.Interface,
	pConf *filter.ConfigParental,
	rlConf *filter.ConfigRuleList,
	sbConf *filter.ConfigSafeBrowsing,
) {
	tb.Helper()

	assertFilterResultsParental(tb, flt, pConf)
	assertFilterResultsRuleList(tb, flt, rlConf)
	assertFilterResultsSafeBrowsing(tb, flt, sbConf)
}

// assertFilterResultsParental is a test helper for asserting a filter's results
// based on parental-protection configuration.
func assertFilterResultsParental(tb testing.TB, f filter.Interface, c *filter.ConfigParental) {
	tb.Helper()

	var wantResAdult, wantResSSGen, wantResSSYT, wantResSvc filter.Result
	if c.Enabled {
		if c.AdultBlockingEnabled {
			wantResAdult = resultAdult
		}

		if c.SafeSearchGeneralEnabled {
			wantResSSGen = resultSafeSearchGen
		}

		if c.SafeSearchYouTubeEnabled {
			wantResSSYT = resultSafeSearchYT
		}

		if len(c.BlockedServices) > 0 {
			wantResSvc = resultBlockedSvc
		}
	}

	checks := container.KeyValues[string, filter.Result]{{
		Key:   filtertest.HostAdultContent,
		Value: wantResAdult,
	}, {
		Key:   filtertest.HostSafeSearchGeneral,
		Value: wantResSSGen,
	}, {
		Key:   filtertest.HostSafeSearchYouTube,
		Value: wantResSSYT,
	}, {
		Key:   filtertest.HostBlockedService1,
		Value: wantResSvc,
	}}

	for _, c := range checks {
		ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)
		r, err := f.FilterRequest(ctx, filtertest.NewARequest(tb, c.Key))
		require.NoError(tb, err)

		filtertest.AssertEqualResult(tb, c.Value, r)
	}
}

// assertFilterResultsRuleList is a test helper for asserting a filter's results
// based on rule-list configuration.
func assertFilterResultsRuleList(tb testing.TB, f filter.Interface, c *filter.ConfigRuleList) {
	tb.Helper()

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)
	r, err := f.FilterRequest(ctx, filtertest.NewARequest(tb, filtertest.HostBlocked))
	require.NoError(tb, err)

	var wantRes filter.Result
	if c.Enabled {
		wantRes = resultRuleList
	}

	filtertest.AssertEqualResult(tb, wantRes, r)
}

// assertFilterResultsSafeBrowsing is a test helper for asserting a filter's
// results based on safe-browsing configuration.
func assertFilterResultsSafeBrowsing(
	tb testing.TB,
	f filter.Interface,
	c *filter.ConfigSafeBrowsing,
) {
	tb.Helper()

	var wantResDanger, wantResNewReg filter.Result
	if c.Enabled {
		if c.DangerousDomainsEnabled {
			wantResDanger = resultDanger
		}

		if c.NewlyRegisteredDomainsEnabled {
			wantResNewReg = resultNewReg
		}
	}

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)
	r, err := f.FilterRequest(ctx, filtertest.NewARequest(tb, filtertest.HostDangerous))
	require.NoError(tb, err)

	filtertest.AssertEqualResult(tb, wantResDanger, r)

	ctx = testutil.ContextWithTimeout(tb, filtertest.Timeout)
	r, err = f.FilterRequest(ctx, filtertest.NewARequest(tb, filtertest.HostNewlyRegistered))
	require.NoError(tb, err)

	filtertest.AssertEqualResult(tb, wantResNewReg, r)
}

func TestDefault_Dispose(t *testing.T) {
	t.Parallel()

	s := newDefault(t)

	testCases := []struct {
		filter filter.Interface
		name   string
	}{{
		name:   "composite",
		filter: &composite.Filter{},
	}, {
		name:   "non_composite",
		filter: filter.Empty{},
	}, {
		name:   "nil",
		filter: nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.NotPanics(t, func() { s.Dispose(tc.filter) })
		})
	}
}

func BenchmarkDefault_ForConfig(b *testing.B) {
	s := newDefault(b)

	ctx := testutil.ContextWithTimeout(b, filtertest.Timeout)

	parental := newFltConfigParental(true, true, true, true)
	ruleList := newFltConfigRuleList(true)
	safeBrowsing := newFltConfigSafeBrowsing(true, true, true, true)

	b.Run("client", func(b *testing.B) {
		conf := newFltConfigCli(parental, ruleList, safeBrowsing)

		// Warmup to fill the pools.
		cliFlt := s.ForConfig(ctx, conf)
		require.NotNil(b, cliFlt)

		s.Dispose(cliFlt)

		b.ReportAllocs()
		for b.Loop() {
			cliFlt = s.ForConfig(ctx, conf)
			s.Dispose(cliFlt)
		}

		require.NotNil(b, cliFlt)
	})

	b.Run("group", func(b *testing.B) {
		conf := &filter.ConfigGroup{
			Parental:     parental,
			RuleList:     ruleList,
			SafeBrowsing: safeBrowsing,
		}

		// Warmup to fill the pools.
		grpFlt := s.ForConfig(ctx, conf)
		require.NotNil(b, grpFlt)

		s.Dispose(grpFlt)

		b.ReportAllocs()
		for b.Loop() {
			grpFlt = s.ForConfig(ctx, conf)
			s.Dispose(grpFlt)
		}

		require.NotNil(b, grpFlt)
	})

	// Most recent results
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/filterstorage
	//	cpu: Apple M4 Pro
	//	BenchmarkDefault_ForConfig/client-14         	23040810	        51.90 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDefault_ForConfig/group-14          	23413891	        50.73 ns/op	       0 B/op	       0 allocs/op
}
