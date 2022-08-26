package filter_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(a.garipov): Try to turn these into table-driven tests.

func TestStorage_FilterFromContext_ruleList_request(t *testing.T) {
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
		ErrColl:                   errColl,
		Resolver:                  nil,
		CacheDir:                  cacheDir,
		CustomFilterCacheSize:     100,
		SafeSearchCacheTTL:        10 * time.Second,
		RefreshIvl:                testRefreshIvl,
	}

	s, err := filter.NewDefaultStorage(c)
	require.NoError(t, err)

	g := &agd.FilteringGroup{
		ID:               "default",
		RuleListIDs:      []agd.FilterListID{testFilterID},
		RuleListsEnabled: true,
	}

	p := &agd.Profile{
		RuleListIDs:      []agd.FilterListID{testFilterID},
		FilteringEnabled: true,
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

		ri := newReqInfo(g, nil, blockedHost, clientIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultBlocked)(nil), r)

		rb, _ := r.(*filter.ResultBlocked)
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

		ri := newReqInfo(g, nil, allowedHost, clientIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultAllowed)(nil), r)

		ra, _ := r.(*filter.ResultAllowed)
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

		ri := newReqInfo(g, nil, blockedClientHost, clientIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultBlocked)(nil), r)

		rb, _ := r.(*filter.ResultBlocked)
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

		ri := newReqInfo(g, nil, allowedClientHost, clientIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultAllowed)(nil), r)

		ra, _ := r.(*filter.ResultAllowed)
		assert.Contains(t, ra.Rule, allowedClientHost)
		assert.Equal(t, ra.List, testFilterID)
	})

	t.Run("blocked_device", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   blockedDeviceFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ri := newReqInfo(g, p, blockedDeviceHost, deviceIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultBlocked)(nil), r)

		rb, _ := r.(*filter.ResultBlocked)
		assert.Contains(t, rb.Rule, blockedDeviceHost)
		assert.Equal(t, rb.List, testFilterID)
	})

	t.Run("allowed_device", func(t *testing.T) {
		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   allowedDeviceFQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		ri := newReqInfo(g, p, allowedDeviceHost, deviceIP, dns.TypeA)
		ctx := agd.ContextWithRequestInfo(context.Background(), ri)

		f := s.FilterFromContext(ctx, ri)
		require.NotNil(t, f)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultAllowed)(nil), r)

		ra, _ := r.(*filter.ResultAllowed)
		assert.Contains(t, ra.Rule, allowedDeviceHost)
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

		ri := newReqInfo(g, nil, otherNetHost, clientIP, dns.TypeA)
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

func TestStorage_FilterFromContext_ruleList_response(t *testing.T) {
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
		ErrColl:                   errColl,
		Resolver:                  nil,
		CacheDir:                  cacheDir,
		CustomFilterCacheSize:     100,
		SafeSearchCacheTTL:        10 * time.Second,
		RefreshIvl:                testRefreshIvl,
	}

	s, err := filter.NewDefaultStorage(c)
	require.NoError(t, err)

	g := &agd.FilteringGroup{
		ID:               "default",
		RuleListIDs:      []agd.FilterListID{testFilterID},
		RuleListsEnabled: true,
	}

	ri := newReqInfo(g, nil, otherNetHost, clientIP, dns.TypeA)
	ctx := agd.ContextWithRequestInfo(context.Background(), ri)

	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)
	testutil.CleanupAndRequireSuccess(t, f.Close)

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

		var r filter.Result
		r, err = f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultBlocked)(nil), r)

		rb, _ := r.(*filter.ResultBlocked)
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

		var r filter.Result
		r, err = f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultAllowed)(nil), r)

		ra, _ := r.(*filter.ResultAllowed)
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

		var r filter.Result
		r, err = f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultBlocked)(nil), r)

		rb, _ := r.(*filter.ResultBlocked)
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

		var r filter.Result
		r, err = f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultAllowed)(nil), r)

		ra, _ := r.(*filter.ResultAllowed)
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

		var r filter.Result
		r, err = f.FilterResponse(ctx, resp, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultBlocked)(nil), r)

		rb, _ := r.(*filter.ResultBlocked)
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

		var r filter.Result
		r, err = f.FilterResponse(ctx, req, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultAllowed)(nil), r)

		ra, _ := r.(*filter.ResultAllowed)
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

		var r filter.Result
		r, err = f.FilterResponse(ctx, req, ri)
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

		var r filter.Result
		r, err = f.FilterResponse(ctx, req, ri)
		require.NoError(t, err)
		require.IsType(t, (*filter.ResultBlocked)(nil), r)

		rb, _ := r.(*filter.ResultBlocked)
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

		var r filter.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		assert.Nil(t, r)
	})
}
