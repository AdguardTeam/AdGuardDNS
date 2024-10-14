package filter_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests and contexts.
const testTimeout = 10 * time.Second

// TODO(a.garipov): Refactor the common stages, such as storage initialization,
// into a single method.

func TestStorage_FilterFromContext(t *testing.T) {
	c := prepareConf(t)
	c.ErrColl = agdtest.NewErrorCollector()

	s := filter.NewDefaultStorage(c)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, s.RefreshInitial(ctx))

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

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, p, blockedHost, clientIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
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

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, p, customHost, clientIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
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

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, &agd.Profile{}, customHost, clientIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		assert.Nil(t, r)
	})
}

func TestStorage_FilterFromContext_customAllow(t *testing.T) {
	errColl := agdtest.NewErrorCollector()
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, safeBrowsingHost+"\n", http.StatusOK)
	hashes, err := hashprefix.NewStorage(safeBrowsingHost)
	require.NoError(t, err)

	c := prepareConf(t)

	safeBrowsing, err := hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          slogutil.NewDiscardLogger(),
		Cloner:          agdtest.NewCloner(),
		CacheManager:    agdcache.EmptyManager{},
		Hashes:          hashes,
		URL:             srvURL,
		ErrColl:         errColl,
		ID:              agd.FilterListIDSafeBrowsing,
		CachePath:       cachePath,
		ReplacementHost: safeBrowsingReplHost,
		Staleness:       filtertest.Staleness,
		CacheTTL:        filtertest.CacheTTL,
		CacheSize:       100,
		MaxSize:         filtertest.FilterMaxSize,
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, safeBrowsing.RefreshInitial(ctx))

	c.ErrColl = errColl
	c.SafeBrowsing = safeBrowsing

	s := filter.NewDefaultStorage(c)
	require.NoError(t, s.RefreshInitial(ctx))

	const safeBrowsingAllowRule = "@@||" + safeBrowsingHost + "^"
	p := &agd.Profile{
		Parental: &agd.ParentalProtectionSettings{
			Enabled: true,
		},
		ID:               "prof1234",
		FilteringEnabled: true,
		SafeBrowsing: &agd.SafeBrowsingSettings{
			Enabled:                     true,
			BlockDangerousDomains:       true,
			BlockNewlyRegisteredDomains: false,
		},
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

	ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
	ri := newReqInfo(t, g, p, safeBrowsingSubHost, clientIP, dns.TypeA)
	ctx = agd.ContextWithRequestInfo(ctx, ri)

	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)

	r, err := f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	ra := testutil.RequireTypeAssert[*filter.ResultAllowed](t, r)

	assert.Equal(t, ra.Rule, agd.FilterRuleText(safeBrowsingAllowRule))
	assert.Equal(t, ra.List, agd.FilterListIDCustom)
}

func TestStorage_FilterFromContext_schedule(t *testing.T) {
	// The current time is 12:00:00, while the schedule allows disabling the
	// parental protection from 11:00:00 until 12:59:59.
	nowTime := time.Date(2021, 1, 1, 12, 0, 0, 0, time.UTC)

	errColl := agdtest.NewErrorCollector()
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, safeBrowsingHost+"\n", http.StatusOK)
	hashes, err := hashprefix.NewStorage(safeBrowsingHost)
	require.NoError(t, err)

	c := prepareConf(t)

	// Use AdultBlocking, because SafeBrowsing is NOT affected by the schedule.
	adultBlocking, err := hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          slogutil.NewDiscardLogger(),
		Cloner:          agdtest.NewCloner(),
		CacheManager:    agdcache.EmptyManager{},
		Hashes:          hashes,
		URL:             srvURL,
		ErrColl:         errColl,
		ID:              agd.FilterListIDAdultBlocking,
		CachePath:       cachePath,
		ReplacementHost: filtertest.SafeBrowsingReplIPv4Str,
		Staleness:       filtertest.Staleness,
		CacheTTL:        filtertest.CacheTTL,
		CacheSize:       100,
		MaxSize:         filtertest.FilterMaxSize,
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, adultBlocking.RefreshInitial(ctx))

	c.Now = func() (t time.Time) {
		return nowTime
	}
	c.ErrColl = errColl
	c.AdultBlocking = adultBlocking

	s := filter.NewDefaultStorage(c)
	require.NoError(t, s.RefreshInitial(ctx))

	// Set up our profile with the schedule that disables filtering at the
	// current moment.
	sch := &agd.ParentalProtectionSchedule{
		TimeZone: agdtime.UTC(),
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

	ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
	ri := newReqInfo(t, g, p, safeBrowsingSubHost, clientIP, dns.TypeA)
	ctx = agd.ContextWithRequestInfo(ctx, ri)

	// The adult blocking filter should not be triggered, since we're within the
	// schedule.
	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)

	r, err := f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	assert.Nil(t, r)

	// Change the schedule and try again.
	sch.Week[int(time.Friday)].End = 11 * 60

	f = s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)

	r, err = f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	rm := testutil.RequireTypeAssert[*filter.ResultModifiedResponse](t, r)

	assert.Equal(t, rm.Rule, agd.FilterRuleText(safeBrowsingHost))
	assert.Equal(t, rm.List, agd.FilterListIDAdultBlocking)

	ans := testutil.RequireTypeAssert[*dns.A](t, rm.Msg.Answer[0])

	ansIP, err := netutil.IPToAddr(ans.A, netutil.AddrFamilyIPv4)
	assert.NoError(t, err)
	assert.Equal(t, filtertest.SafeBrowsingReplIPv4, ansIP)
}

func TestStorage_FilterFromContext_ruleList_request(t *testing.T) {
	c := prepareConf(t)
	c.ErrColl = agdtest.NewErrorCollector()

	s := filter.NewDefaultStorage(c)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, s.RefreshInitial(ctx))

	g := &agd.FilteringGroup{
		ID:               "default",
		RuleListIDs:      []agd.FilterListID{testFilterID},
		RuleListsEnabled: true,
	}

	t.Run("blocked", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   blockedFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, nil, blockedHost, clientIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, blockedHost)
		assert.Equal(t, rb.List, testFilterID)
	})

	t.Run("allowed", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   allowedFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, nil, allowedHost, clientIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		ra := testutil.RequireTypeAssert[*filter.ResultAllowed](t, r)

		assert.Contains(t, ra.Rule, allowedHost)
		assert.Equal(t, ra.List, testFilterID)
	})

	t.Run("blocked_client", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   blockedClientFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, nil, blockedClientHost, clientIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, blockedClientHost)
		assert.Equal(t, rb.List, testFilterID)
	})

	t.Run("allowed_client", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   allowedClientFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, nil, allowedClientHost, clientIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		ra := testutil.RequireTypeAssert[*filter.ResultAllowed](t, r)

		assert.Contains(t, ra.Rule, allowedClientHost)
		assert.Equal(t, ra.List, testFilterID)
	})

	t.Run("none", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   otherNetFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, nil, otherNetHost, clientIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		assert.Nil(t, r)
	})
}

func TestStorage_FilterFromContext_customDevice(t *testing.T) {
	c := prepareConf(t)
	c.ErrColl = agdtest.NewErrorCollector()

	s := filter.NewDefaultStorage(c)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, s.RefreshInitial(ctx))

	g := &agd.FilteringGroup{}
	p := &agd.Profile{
		CustomRules: []agd.FilterRuleText{
			`||blocked-device.example.com^$client="My Device"`,
			`@@||allowed-device.example.com^$client="My Device"`,
		},
		FilteringEnabled: true,
		RuleListsEnabled: true,
	}

	t.Run("blocked_device", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   blockedDeviceFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, p, blockedDeviceHost, deviceIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, blockedDeviceHost)
		assert.Equal(t, rb.List, agd.FilterListIDCustom)
	})

	t.Run("allowed_device", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   allowedDeviceFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
		ri := newReqInfo(t, g, p, allowedDeviceHost, deviceIP, dns.TypeA)
		ctx = agd.ContextWithRequestInfo(ctx, ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		ra := testutil.RequireTypeAssert[*filter.ResultAllowed](t, r)

		assert.Contains(t, ra.Rule, allowedDeviceHost)
		assert.Equal(t, ra.List, agd.FilterListIDCustom)
	})
}

func TestStorage_FilterFromContext_ruleList_response(t *testing.T) {
	c := prepareConf(t)
	c.ErrColl = agdtest.NewErrorCollector()

	s := filter.NewDefaultStorage(c)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, s.RefreshInitial(ctx))

	g := &agd.FilteringGroup{
		ID:               "default",
		RuleListIDs:      []agd.FilterListID{testFilterID},
		RuleListsEnabled: true,
	}

	ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
	ri := newReqInfo(t, g, nil, otherNetHost, clientIP, dns.TypeA)
	ctx = agd.ContextWithRequestInfo(ctx, ri)

	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)

	question := []dns.Question{{
		Name:   otherNetFQDN,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}

	t.Run("blocked_a", func(t *testing.T) {
		resp := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.A{
				A: blockedIP4,
			}},
		}

		r, err := f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, blockedIP4.String())
		assert.Equal(t, rb.List, testFilterID)
	})

	t.Run("allowed_a", func(t *testing.T) {
		resp := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.A{
				A: allowedIP4,
			}},
		}

		r, err := f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)

		ra := testutil.RequireTypeAssert[*filter.ResultAllowed](t, r)

		assert.Contains(t, ra.Rule, allowedIP4.String())
		assert.Equal(t, ra.List, testFilterID)
	})

	t.Run("blocked_cname", func(t *testing.T) {
		resp := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.CNAME{
				Target: blockedFQDN,
			}},
		}

		r, err := f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, blockedHost)
		assert.Equal(t, rb.List, testFilterID)
	})

	t.Run("allowed_cname", func(t *testing.T) {
		resp := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.CNAME{
				Target: allowedFQDN,
			}},
		}

		r, err := f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)

		ra := testutil.RequireTypeAssert[*filter.ResultAllowed](t, r)

		assert.Contains(t, ra.Rule, allowedHost)
		assert.Equal(t, ra.List, testFilterID)
	})

	t.Run("blocked_client", func(t *testing.T) {
		resp := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.CNAME{
				Target: blockedClientFQDN,
			}},
		}

		r, err := f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, blockedClientHost)
		assert.Equal(t, rb.List, testFilterID)
	})

	t.Run("allowed_client", func(t *testing.T) {
		req := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.CNAME{
				Target: allowedClientFQDN,
			}},
		}

		r, err := f.FilterResponse(ctx, req, ri)
		require.NoError(t, err)

		ra := testutil.RequireTypeAssert[*filter.ResultAllowed](t, r)

		assert.Contains(t, ra.Rule, allowedClientHost)
		assert.Equal(t, ra.List, testFilterID)
	})

	t.Run("exception_cname", func(t *testing.T) {
		req := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.CNAME{
				Target: "cname.exception.",
			}},
		}

		r, err := f.FilterResponse(ctx, req, ri)
		require.NoError(t, err)

		assert.Nil(t, r)
	})

	t.Run("exception_cname_blocked", func(t *testing.T) {
		req := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.CNAME{
				Target: "cname.blocked.",
			}},
		}

		r, err := f.FilterResponse(ctx, req, ri)
		require.NoError(t, err)

		rb := testutil.RequireTypeAssert[*filter.ResultBlocked](t, r)

		assert.Contains(t, rb.Rule, "cname.blocked")
		assert.Equal(t, rb.List, testFilterID)
	})

	t.Run("none", func(t *testing.T) {
		req := &dns.Msg{
			Question: question,
			Answer: []dns.RR{&dns.CNAME{
				Target: otherOrgFQDN,
			}},
		}

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		assert.Nil(t, r)
	})
}

func TestStorage_FilterFromContext_safeBrowsing(t *testing.T) {
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, safeBrowsingHost+"\n", http.StatusOK)
	hashes, err := hashprefix.NewStorage("")
	require.NoError(t, err)

	errColl := agdtest.NewErrorCollector()

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	safeBrowsing, err := hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          slogutil.NewDiscardLogger(),
		Cloner:          agdtest.NewCloner(),
		CacheManager:    agdcache.EmptyManager{},
		Hashes:          hashes,
		URL:             srvURL,
		ErrColl:         errColl,
		ID:              agd.FilterListIDSafeBrowsing,
		CachePath:       cachePath,
		ReplacementHost: safeBrowsingReplHost,
		Staleness:       filtertest.Staleness,
		CacheTTL:        filtertest.CacheTTL,
		CacheSize:       100,
		MaxSize:         filtertest.FilterMaxSize,
	})
	require.NoError(t, err)
	require.NoError(t, safeBrowsing.RefreshInitial(ctx))

	c := prepareConf(t)
	c.ErrColl = errColl
	c.SafeBrowsing = safeBrowsing

	s := filter.NewDefaultStorage(c)
	require.NoError(t, s.RefreshInitial(ctx))

	g := &agd.FilteringGroup{
		ID:                          "default",
		RuleListIDs:                 []agd.FilterListID{},
		ParentalEnabled:             true,
		SafeBrowsingEnabled:         true,
		BlockDangerousDomains:       true,
		BlockNewlyRegisteredDomains: true,
	}

	// Test

	req := &dns.Msg{
		Question: []dns.Question{{
			Name:   safeBrowsingSubFQDN,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
	ri := newReqInfo(t, g, nil, safeBrowsingSubHost, clientIP, dns.TypeA)
	ctx = agd.ContextWithRequestInfo(ctx, ri)

	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)

	r, err := f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	rm := testutil.RequireTypeAssert[*filter.ResultModifiedRequest](t, r)

	assert.Equal(t, rm.Msg.Question[0].Name, safeBrowsingReplFQDN)
	assert.Equal(t, rm.Rule, agd.FilterRuleText(safeBrowsingHost))
	assert.Equal(t, rm.List, agd.FilterListIDSafeBrowsing)
}

func TestStorage_FilterFromContext_safeSearch(t *testing.T) {
	c := prepareConf(t)

	s := filter.NewDefaultStorage(c)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, s.RefreshInitial(ctx))

	g := &agd.FilteringGroup{
		ID:                "default",
		ParentalEnabled:   true,
		GeneralSafeSearch: true,
	}

	ttl := uint32(agdtest.FilteredResponseTTLSec)

	testCases := []struct {
		name    string
		host    string
		want    []dns.RR
		rrtype  uint16
		wantReq bool
	}{{
		want: []dns.RR{
			dnsservertest.NewA(safeSearchIPv4Host, ttl, safeSearchIPRespIP4),
		},
		name:    "ip4",
		host:    safeSearchIPv4Host,
		rrtype:  dns.TypeA,
		wantReq: false,
	}, {
		want: []dns.RR{
			dnsservertest.NewAAAA(safeSearchIPv6Host, ttl, safeSearchIPRespIP6),
		},
		name:    "ip6",
		host:    safeSearchIPv6Host,
		rrtype:  dns.TypeAAAA,
		wantReq: false,
	}, {
		want:    nil,
		name:    "host_ip4",
		host:    safeSearchHost,
		rrtype:  dns.TypeA,
		wantReq: true,
	}, {
		want:    nil,
		name:    "host_ip6",
		host:    safeSearchHost,
		rrtype:  dns.TypeAAAA,
		wantReq: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
			ri := newReqInfo(t, g, nil, tc.host, clientIP, tc.rrtype)
			ctx = agd.ContextWithRequestInfo(ctx, ri)

			f := s.FilterFromContext(ctx, ri)
			require.NotNil(t, f)

			req := dnsservertest.CreateMessage(tc.host, tc.rrtype)

			r, err := f.FilterRequest(ctx, req, ri)
			require.NoError(t, err)
			require.NotNil(t, r)

			id, rule := r.MatchedRule()
			assert.Contains(t, rule, tc.host)
			assert.Equal(t, id, agd.FilterListIDGeneralSafeSearch)

			var msg *dns.Msg
			if tc.wantReq {
				rm := testutil.RequireTypeAssert[*filter.ResultModifiedRequest](t, r)

				msg = rm.Msg
			} else {
				rm := testutil.RequireTypeAssert[*filter.ResultModifiedResponse](t, r)

				msg = rm.Msg
			}

			require.NotNil(t, msg)

			assert.Equal(t, tc.wantReq, !msg.Response)
			assert.Equal(t, tc.want, msg.Answer)
		})
	}
}

// Typed sinks for benchmarks.
var (
	errSink error
)

func BenchmarkStorage_DefaultStorage_Initialize(b *testing.B) {
	c := prepareConf(b)
	c.ErrColl = agdtest.NewErrorCollector()

	s := filter.NewDefaultStorage(c)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		errSink = s.RefreshInitial(ctx)
	}

	assert.NoError(b, errSink)

	// Recent result on MBP 15:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkStorage_DefaultStorage_Initialize-12	5301	221029 ns/op	260449 B/op		806 allocs/op
}
