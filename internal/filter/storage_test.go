package filter_test

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(a.garipov): Refactor the common stages, such as storage initialization,
// into a single method.

func TestStorage_FilterFromContext(t *testing.T) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) { panic("not implemented") },
	}

	fltsURL, svcsURL, ssURL, cacheDir := prepareIndex(t)
	c := &filter.DefaultStorageConfig{
		BlockedServiceIndexURL:    svcsURL,
		FilterIndexURL:            fltsURL,
		GeneralSafeSearchRulesURL: ssURL,
		YoutubeSafeSearchRulesURL: ssURL,
		SafeBrowsing:              &filter.HashPrefixConfig{},
		AdultBlocking:             &filter.HashPrefixConfig{},
		CacheDir:                  cacheDir,
		ErrColl:                   errColl,
		CustomFilterCacheSize:     100,
		RefreshIvl:                testRefreshIvl,
	}

	s, err := filter.NewDefaultStorage(c)
	require.NoError(t, err)

	p := &agd.Profile{
		ID: "prof1234",
		RuleListIDs: []agd.FilterListID{
			testFilterID,
		},
		CustomRules: []agd.FilterRuleText{
			customRule,
		},
		FilteringEnabled: true,
	}

	g := &agd.FilteringGroup{
		ID:               "default",
		RuleListIDs:      []agd.FilterListID{testFilterID},
		RuleListsEnabled: true,
	}

	t.Run("filter_list", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   blockedFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ri := newReqInfo(g, p, blockedHost, clientIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, blockedHost)
		assert.Equal(t, rb.List, testFilterID)
	})

	t.Run("custom", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   customFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ri := newReqInfo(g, p, customHost, clientIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, customHost)
		assert.Equal(t, rb.List, agd.FilterListIDCustom)
	})

	t.Run("unknown_profile", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   customFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ri := newReqInfo(g, &agd.Profile{}, customHost, clientIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		assert.Nil(t, r)
	})
}

func TestStorage_FilterFromContext_customAllow(t *testing.T) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) { panic("not implemented") },
	}

	resolver := &agdtest.Resolver{
		OnLookupIP: func(
			_ context.Context,
			_ netutil.AddrFamily,
			_ string,
		) (ips []net.IP, err error) {
			return []net.IP{safeBrowsingSafeIP4}, nil
		},
	}

	// Initialize the hashes file and use it with the storage.
	tmpFile, err := os.CreateTemp(t.TempDir(), "")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return os.Remove(tmpFile.Name()) })

	_, err = io.WriteString(tmpFile, safeBrowsingHost+"\n")
	require.NoError(t, err)

	hashes, err := filter.NewHashStorage(&filter.HashStorageConfig{
		CachePath:  tmpFile.Name(),
		RefreshIvl: 1 * time.Hour,
	})
	require.NoError(t, err)

	fltsURL, svcsURL, ssURL, cacheDir := prepareIndex(t)
	c := &filter.DefaultStorageConfig{
		BlockedServiceIndexURL:    svcsURL,
		FilterIndexURL:            fltsURL,
		GeneralSafeSearchRulesURL: ssURL,
		YoutubeSafeSearchRulesURL: ssURL,
		SafeBrowsing: &filter.HashPrefixConfig{
			Hashes:          hashes,
			ReplacementHost: safeBrowsingSafeHost,
			CacheTTL:        10 * time.Second,
			CacheSize:       100,
		},
		AdultBlocking:         &filter.HashPrefixConfig{},
		Now:                   time.Now,
		ErrColl:               errColl,
		Resolver:              resolver,
		CacheDir:              cacheDir,
		CustomFilterCacheSize: 100,
		RefreshIvl:            testRefreshIvl,
	}

	s, err := filter.NewDefaultStorage(c)
	require.NoError(t, err)

	const safeBrowsingAllowRule = "@@||" + safeBrowsingHost + "^"
	p := &agd.Profile{
		Parental: &agd.ParentalProtectionSettings{
			Enabled: true,
		},
		ID:                  "prof1234",
		FilteringEnabled:    true,
		SafeBrowsingEnabled: true,
		CustomRules: []agd.FilterRuleText{
			safeBrowsingAllowRule,
		},
	}

	g := &agd.FilteringGroup{
		ID:          "default",
		RuleListIDs: []agd.FilterListID{},
	}

	req := &dns.Msg{
		Question: []dns.Question{{
			Name:   safeBrowsingSubFQDN,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	ri := newReqInfo(g, p, safeBrowsingSubHost, clientIP, dns.TypeA)
	ctx := agd.ContextWithRequestInfo(context.Background(), ri)

	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)
	testutil.CleanupAndRequireSuccess(t, f.Close)

	r, err := f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	ra := testutil.RequireTypeAssert[*filter.ResultAllowed](t, r)

	assert.Equal(t, ra.Rule, agd.FilterRuleText(safeBrowsingAllowRule))
	assert.Equal(t, ra.List, agd.FilterListIDCustom)
}

func TestStorage_FilterFromContext_schedule(t *testing.T) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) { panic("not implemented") },
	}

	resolver := &agdtest.Resolver{
		OnLookupIP: func(
			_ context.Context,
			_ netutil.AddrFamily,
			_ string,
		) (ips []net.IP, err error) {
			return []net.IP{safeBrowsingSafeIP4}, nil
		},
	}

	// The current time is 12:00:00, while the schedule allows disabling the
	// parental protection from 11:00:00 until 12:59:59.
	nowTime := time.Date(2021, 1, 1, 12, 0, 0, 0, time.UTC)
	now := func() (t time.Time) {
		return nowTime
	}

	// Initialize the hashes file and use it with the storage.
	tmpFile, err := os.CreateTemp(t.TempDir(), "")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return os.Remove(tmpFile.Name()) })

	_, err = io.WriteString(tmpFile, safeBrowsingHost+"\n")
	require.NoError(t, err)

	hashes, err := filter.NewHashStorage(&filter.HashStorageConfig{
		CachePath:  tmpFile.Name(),
		RefreshIvl: 1 * time.Hour,
	})
	require.NoError(t, err)

	fltsURL, svcsURL, ssURL, cacheDir := prepareIndex(t)
	c := &filter.DefaultStorageConfig{
		BlockedServiceIndexURL:    svcsURL,
		FilterIndexURL:            fltsURL,
		GeneralSafeSearchRulesURL: ssURL,
		YoutubeSafeSearchRulesURL: ssURL,
		SafeBrowsing:              &filter.HashPrefixConfig{},
		// Use AdultBlocking, because SafeBrowsing is NOT affected by the
		// schedule.
		AdultBlocking: &filter.HashPrefixConfig{
			Hashes:          hashes,
			ReplacementHost: safeBrowsingSafeHost,
			CacheTTL:        10 * time.Second,
			CacheSize:       100,
		},
		Now:                   now,
		ErrColl:               errColl,
		Resolver:              resolver,
		CacheDir:              cacheDir,
		CustomFilterCacheSize: 100,
		RefreshIvl:            testRefreshIvl,
	}

	s, err := filter.NewDefaultStorage(c)
	require.NoError(t, err)

	// Set up our profile with the schedule that disables filtering at the
	// current moment.
	sch := &agd.ParentalProtectionSchedule{
		TimeZone: time.UTC,
		Week: &agd.WeeklySchedule{
			time.Sunday:    agd.ZeroLengthDayRange(),
			time.Monday:    agd.ZeroLengthDayRange(),
			time.Tuesday:   agd.ZeroLengthDayRange(),
			time.Wednesday: agd.ZeroLengthDayRange(),
			time.Thursday:  agd.ZeroLengthDayRange(),

			// nowTime is on Friday.
			time.Friday: agd.DayRange{
				Start: 11 * 60,
				End:   12 * 60,
			},

			time.Saturday: agd.ZeroLengthDayRange(),
		},
	}

	p := &agd.Profile{
		Parental: &agd.ParentalProtectionSettings{
			Schedule:   sch,
			Enabled:    true,
			BlockAdult: true,
		},
		ID:               "prof1234",
		FilteringEnabled: true,
	}

	g := &agd.FilteringGroup{
		ID:          "default",
		RuleListIDs: []agd.FilterListID{},
	}

	req := &dns.Msg{
		Question: []dns.Question{{
			Name:   safeBrowsingSubFQDN,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	ri := newReqInfo(g, p, safeBrowsingSubHost, clientIP, dns.TypeA)
	ctx := agd.ContextWithRequestInfo(context.Background(), ri)

	// The adult blocking filter should not be triggered, since we're within the
	// schedule.
	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)
	testutil.CleanupAndRequireSuccess(t, f.Close)

	r, err := f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	assert.Nil(t, r)

	// Change the schedule and try again.
	sch.Week[int(time.Friday)].End = 11 * 60

	f = s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)
	testutil.CleanupAndRequireSuccess(t, f.Close)

	r, err = f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	rm := testutil.RequireTypeAssert[*filter.ResultModified](t, r)

	assert.Equal(t, rm.Rule, agd.FilterRuleText(safeBrowsingHost))
	assert.Equal(t, rm.List, agd.FilterListIDAdultBlocking)
}

var (
	defaultStorageSink *filter.DefaultStorage
	errSink            error
)

func BenchmarkStorage_NewDefaultStorage(b *testing.B) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) { panic("not implemented") },
	}

	fltsURL, svcsURL, ssURL, cacheDir := prepareIndex(b)
	c := &filter.DefaultStorageConfig{
		BlockedServiceIndexURL:    svcsURL,
		FilterIndexURL:            fltsURL,
		GeneralSafeSearchRulesURL: ssURL,
		YoutubeSafeSearchRulesURL: ssURL,
		SafeBrowsing:              &filter.HashPrefixConfig{},
		AdultBlocking:             &filter.HashPrefixConfig{},
		CacheDir:                  cacheDir,
		ErrColl:                   errColl,
		CustomFilterCacheSize:     100,
		RefreshIvl:                testRefreshIvl,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		defaultStorageSink, errSink = filter.NewDefaultStorage(c)
	}

	assert.NotNil(b, defaultStorageSink)
	assert.NoError(b, errSink)

	// Recent result on MBP 15:
	//
	//	goos: darwin
	//	goarch: amd64
	//	cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
	//	BenchmarkStorage_NewDefaultStorage/success-12    3238    344513 ns/op    198096 B/op    952 allocs/op
}
