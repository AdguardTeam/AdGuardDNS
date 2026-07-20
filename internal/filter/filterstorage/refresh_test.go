package filterstorage_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterstorage"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault_Refresh(t *testing.T) {
	// TODO(a.garipov):  Consider ways to DRY this code with [newDefault].
	const (
		blockRule   = filtertest.RuleBlockStr + "\n"
		blockDomain = filtertest.HostBlocked + "\n"
		ssGenRule   = filtertest.RuleSafeSearchGeneralHostStr + "\n"
		ssYTRule    = filtertest.RuleSafeSearchYouTubeStr + "\n"
	)

	rlCh := make(chan unit, 1)
	_, ruleListURL := filtertest.PrepareRefreshable(t, rlCh, blockRule, http.StatusOK)
	rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())

	rlIdxCh := make(chan unit, 1)
	_, ruleListIdxURL := filtertest.PrepareRefreshable(t, rlIdxCh, string(rlIdxData), http.StatusOK)

	catCh := make(chan unit, 1)
	_, catURL := filtertest.PrepareRefreshable(t, catCh, blockDomain, http.StatusOK)
	catIdxData := filtertest.NewCategoryIndex(catURL.String())

	catIdxCh := make(chan unit, 1)
	_, catIdxURL := filtertest.PrepareRefreshable(t, catIdxCh, string(catIdxData), http.StatusOK)

	ssGenCh, ssYTCh := make(chan unit, 1), make(chan unit, 1)
	_, safeSearchGenURL := filtertest.PrepareRefreshable(t, ssGenCh, ssGenRule, http.StatusOK)
	_, safeSearchYTURL := filtertest.PrepareRefreshable(t, ssYTCh, ssYTRule, http.StatusOK)

	svcIdxCh := make(chan unit, 1)
	_, svcIdxURL := filtertest.PrepareRefreshable(
		t,
		svcIdxCh,
		filtertest.BlockedServiceIndex,
		http.StatusOK,
	)

	idxStorage := newRuleListIdxStorage(t, ruleListIdxURL)
	rlStorage := newRuleListStorage(t, idxStorage, filtertest.Staleness)
	c := newDisabledConfig(t, rlStorage, newIndexConfig(catIdxURL))
	c.BlockedServices = newConfigBlockedServices(svcIdxURL)
	c.SafeSearchGeneral = newConfigSafeSearch(safeSearchGenURL, filter.IDGeneralSafeSearch)
	c.SafeSearchYouTube = newConfigSafeSearch(safeSearchYTURL, filter.IDYoutubeSafeSearch)
	c.Typosquatting = &filterstorage.TyposquattingConfig{}
	c.Homoglyph = &filterstorage.HomoglyphConfig{}

	s, err := filterstorage.New(c)
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = s.RefreshInitial(ctx)
	require.NoError(t, err)

	testutil.RequireReceive(t, rlCh, filtertest.Timeout)
	testutil.RequireReceive(t, catCh, filtertest.Timeout)
	testutil.RequireReceive(t, rlIdxCh, filtertest.Timeout)
	testutil.RequireReceive(t, catIdxCh, filtertest.Timeout)
	testutil.RequireReceive(t, ssGenCh, filtertest.Timeout)
	testutil.RequireReceive(t, ssYTCh, filtertest.Timeout)
	testutil.RequireReceive(t, svcIdxCh, filtertest.Timeout)

	ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = s.Refresh(ctx)
	require.NoError(t, err)

	// Make sure that the servers weren't called the second time.
	require.Empty(t, rlCh)
	require.Empty(t, catCh)
	require.Empty(t, rlIdxCh)
	require.Empty(t, catIdxCh)
	require.Empty(t, ssGenCh)
	require.Empty(t, ssYTCh)
	require.Empty(t, svcIdxCh)
}

func TestDefault_Refresh_usePrevious(t *testing.T) {
	const (
		blockRule   = filtertest.RuleBlockStr + "\n"
		blockDomain = filtertest.HostBlocked + "\n"
	)

	collector := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			errStatus := &agdhttp.StatusError{}
			assert.ErrorAs(t, err, &errStatus)
			assert.Equal(t, http.StatusOK, errStatus.Expected)
			assert.Equal(t, http.StatusNotFound, errStatus.Got)
			assert.Equal(t, filtertest.ServerName, errStatus.ServerName)
		},
	}

	fltConf := &filter.ConfigClient{
		CustomFilter:   &filter.ConfigCustomFilter{},
		CustomRuleList: &filter.ConfigCustomRuleList{},
		Parental: &filter.ConfigParental{
			Categories: &filter.ConfigCategories{},
		},
		RuleList: &filter.ConfigRuleList{},
		SafeBrowsing: &filter.ConfigSafeBrowsing{
			Homoglyph:     &filter.ConfigHomoglyph{},
			Typosquatting: &filter.ConfigTyposquatting{},
		},
	}

	require.True(t, t.Run("rule_list", func(t *testing.T) {
		codeCh := make(chan int, 2)
		codeCh <- http.StatusOK
		codeCh <- http.StatusNotFound
		ruleListURL := newCodeServer(t, blockRule, codeCh)

		rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())
		_, rlIdxURL := filtertest.PrepareRefreshable(t, nil, string(rlIdxData), http.StatusOK)

		_, catURL := filtertest.PrepareRefreshable(t, nil, blockDomain, http.StatusOK)
		catIdxData := filtertest.NewCategoryIndex(catURL.String())
		_, catIdxURL := filtertest.PrepareRefreshable(t, nil, string(catIdxData), http.StatusOK)

		indexStorage := newRuleListIdxStorage(t, rlIdxURL)
		rlStorage := newRuleListStorage(t, indexStorage, 1*time.Microsecond)
		c := newDisabledConfig(t, rlStorage, newIndexConfig(catIdxURL))
		c.ErrColl = collector

		s, err := filterstorage.New(c)
		require.NoError(t, err)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		err = s.RefreshInitial(ctx)
		require.NoError(t, err)

		fltConf.RuleList.Enabled = true
		fltConf.RuleList.IDs = []filter.ID{filtertest.RuleListID1}

		testUsePreviousFilter(t, s, fltConf, resultRuleList)
	}))

	fltConf.RuleList.Enabled = false

	require.True(t, t.Run("category", func(t *testing.T) {
		codeCh := make(chan int, 2)
		codeCh <- http.StatusOK
		codeCh <- http.StatusNotFound
		catURL := newCodeServer(t, blockDomain, codeCh)

		catIdxData := filtertest.NewCategoryIndex(catURL.String())
		_, catIdxURL := filtertest.PrepareRefreshable(t, nil, string(catIdxData), http.StatusOK)

		_, ruleListURL := filtertest.PrepareRefreshable(t, nil, blockRule, http.StatusOK)
		rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())
		_, rlIdxURL := filtertest.PrepareRefreshable(t, nil, string(rlIdxData), http.StatusOK)

		idxConf := newIndexConfig(catIdxURL)
		idxConf.Staleness = 1 * time.Microsecond

		rlStorage := newRuleListStorage(t, newRuleListIdxStorage(t, rlIdxURL), filtertest.Staleness)
		c := newDisabledConfig(t, rlStorage, idxConf)
		c.ErrColl = collector

		s, err := filterstorage.New(c)
		require.NoError(t, err)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		err = s.RefreshInitial(ctx)
		require.NoError(t, err)

		resultCategory := &filter.ResultBlocked{
			List: filter.IDCategory,
			Rule: filter.RuleText(filtertest.CategoryIDStr),
		}

		fltConf.Parental.Enabled = true
		fltConf.Parental.Categories.Enabled = true
		fltConf.Parental.Categories.IDs = []filter.CategoryID{filtertest.CategoryID}

		testUsePreviousFilter(t, s, fltConf, resultCategory)
	}))
}

// testUsePreviousFilter is a helper that makes sure that a filter continues to
// use the previous version when refresh fails.
func testUsePreviousFilter(
	tb testing.TB,
	s *filterstorage.Default,
	fltConf *filter.ConfigClient,
	wantRes filter.Result,
) {
	tb.Helper()

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)
	f := s.ForConfig(ctx, fltConf)
	require.NotNil(tb, f)

	req := filtertest.NewARequest(tb, filtertest.HostBlocked)
	r, err := f.FilterRequest(ctx, req)
	require.NoError(tb, err)

	filtertest.AssertEqualResult(tb, wantRes, r)

	err = s.Refresh(ctx)
	require.NoError(tb, err)

	f = s.ForConfig(ctx, fltConf)
	require.NotNil(tb, f)

	r, err = f.FilterRequest(ctx, req)
	require.NotNil(tb, r)
	require.NoError(tb, err)

	filtertest.AssertEqualResult(tb, wantRes, r)
}

// newCodeServer is a helper that creates a server responding with text and
// response-code values sent over codeCh.
func newCodeServer(tb testing.TB, text string, codeCh <-chan int) (srvURL *url.URL) {
	tb.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		w.Header().Set(httphdr.Server, filtertest.ServerName)

		code, ok := testutil.RequireReceive(tb, codeCh, filtertest.Timeout)
		require.True(pt, ok)

		w.WriteHeader(code)

		_, writeErr := io.WriteString(w, text)
		require.NoError(pt, writeErr)
	}))

	tb.Cleanup(srv.Close)

	srvURL, err := agdhttp.ParseHTTPURL(srv.URL)
	require.NoError(tb, err)

	return srvURL
}
