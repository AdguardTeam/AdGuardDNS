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
		blockRule = filtertest.RuleBlockStr + "\n"
		ssGenRule = filtertest.RuleSafeSearchGeneralHostStr + "\n"
		ssYTRule  = filtertest.RuleSafeSearchYouTubeStr + "\n"
	)

	rlCh := make(chan unit, 1)
	_, ruleListURL := filtertest.PrepareRefreshable(t, rlCh, blockRule, http.StatusOK)
	rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())

	rlIdxCh := make(chan unit, 1)
	_, ruleListIdxURL := filtertest.PrepareRefreshable(t, rlIdxCh, string(rlIdxData), http.StatusOK)

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

	c := newDisabledConfig(t, newConfigRuleLists(ruleListIdxURL))
	c.BlockedServices = newConfigBlockedServices(svcIdxURL)
	c.SafeSearchGeneral = newConfigSafeSearch(safeSearchGenURL, filter.IDGeneralSafeSearch)
	c.SafeSearchYouTube = newConfigSafeSearch(safeSearchYTURL, filter.IDYoutubeSafeSearch)

	s, err := filterstorage.New(c)
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = s.RefreshInitial(ctx)
	require.NoError(t, err)

	testutil.RequireReceive(t, rlCh, filtertest.Timeout)
	testutil.RequireReceive(t, rlIdxCh, filtertest.Timeout)
	testutil.RequireReceive(t, ssGenCh, filtertest.Timeout)
	testutil.RequireReceive(t, ssYTCh, filtertest.Timeout)
	testutil.RequireReceive(t, svcIdxCh, filtertest.Timeout)

	assert.True(t, s.HasListID(filtertest.RuleListID1))

	ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = s.Refresh(ctx)
	require.NoError(t, err)

	// Make sure that the servers weren't called the second time.
	require.Empty(t, rlCh)
	require.Empty(t, rlIdxCh)
	require.Empty(t, ssGenCh)
	require.Empty(t, ssYTCh)
	require.Empty(t, svcIdxCh)

	assert.True(t, s.HasListID(filtertest.RuleListID1))
}

func TestDefault_Refresh_usePrevious(t *testing.T) {
	const (
		blockRule = filtertest.RuleBlockStr + "\n"
	)

	codeCh := make(chan int, 2)
	codeCh <- http.StatusOK
	codeCh <- http.StatusNotFound
	ruleListURL := newCodeServer(t, blockRule, codeCh)

	rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())
	_, ruleListIdxURL := filtertest.PrepareRefreshable(t, nil, string(rlIdxData), http.StatusOK)

	// Use a smaller staleness value to make sure that the filter is refreshed.
	ruleListsConf := newConfigRuleLists(ruleListIdxURL)
	ruleListsConf.Staleness = 1 * time.Microsecond

	c := newDisabledConfig(t, ruleListsConf)
	c.RuleLists = ruleListsConf
	c.ErrColl = &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			errStatus := &agdhttp.StatusError{}
			assert.ErrorAs(t, err, &errStatus)
			assert.Equal(t, errStatus.Expected, http.StatusOK)
			assert.Equal(t, errStatus.Got, http.StatusNotFound)
			assert.Equal(t, errStatus.ServerName, filtertest.ServerName)
		},
	}

	s, err := filterstorage.New(c)
	require.NoError(t, err)

	// The first refresh, success.
	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = s.RefreshInitial(ctx)
	require.NoError(t, err)
	require.True(t, s.HasListID(filtertest.RuleListID1))

	fltConf := &filter.ConfigClient{
		Custom:   &filter.ConfigCustom{},
		Parental: &filter.ConfigParental{},
		RuleList: &filter.ConfigRuleList{
			IDs:     []filter.ID{filtertest.RuleListID1},
			Enabled: true,
		},
		SafeBrowsing: &filter.ConfigSafeBrowsing{},
	}

	f := s.ForConfig(ctx, fltConf)
	require.NotNil(t, f)

	req := filtertest.NewARequest(t, filtertest.HostBlocked)
	r, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	filtertest.AssertEqualResult(t, resultRuleList, r)

	// The second refresh, not found.  The older version of the rule-list filter
	// must still be used.
	err = s.Refresh(ctx)
	require.NoError(t, err)
	require.True(t, s.HasListID(filtertest.RuleListID1))

	f = s.ForConfig(ctx, fltConf)
	require.NotNil(t, f)

	r, err = f.FilterRequest(ctx, req)
	require.NotNil(t, r)
	require.NoError(t, err)

	filtertest.AssertEqualResult(t, resultRuleList, r)
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
