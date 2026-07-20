package ruleliststorage_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/ruleliststorage"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unit is a convenient alias for struct{}.
type unit = struct{}

func TestDefault_Refresh(t *testing.T) {
	t.Parallel()

	rlCh := make(chan unit, 1)
	_, ruleListURL := filtertest.PrepareRefreshable(t, rlCh, testFilterData, http.StatusOK)
	rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())

	rlIdxCh := make(chan unit, 1)
	_, ruleListIdxURL := filtertest.PrepareRefreshable(
		t,
		rlIdxCh,
		string(rlIdxData),
		http.StatusOK,
	)

	s := newDefault(t, &ruleliststorage.Config{
		IndexStorage: newRuleListIdxStorage(t, ruleListIdxURL),
	})

	testutil.RequireReceive(t, rlCh, filtertest.Timeout)
	testutil.RequireReceive(t, rlIdxCh, filtertest.Timeout)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

	assert.True(t, s.HasListID(ctx, filtertest.RuleListID1))
	assert.False(t, s.HasListID(ctx, filtertest.RuleListID2))

	err := s.Refresh(ctx)
	require.NoError(t, err)

	// Make sure that the servers weren't called the second time.
	require.Empty(t, rlCh)
	require.Empty(t, rlIdxCh)

	assert.True(t, s.HasListID(ctx, filtertest.RuleListID1))
	assert.False(t, s.HasListID(ctx, filtertest.RuleListID2))
}

func TestDefault_Refresh_usePrevious(t *testing.T) {
	t.Parallel()

	codeCh := make(chan int, 2)
	codeCh <- http.StatusOK
	codeCh <- http.StatusNotFound
	ruleListURL := newCodeServer(t, testFilterData, codeCh)

	rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())
	_, rlIdxURL := filtertest.PrepareRefreshable(t, nil, string(rlIdxData), http.StatusOK)

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			errStatus := &agdhttp.StatusError{}
			assert.ErrorAs(t, err, &errStatus)
			assert.Equal(t, http.StatusOK, errStatus.Expected)
			assert.Equal(t, http.StatusNotFound, errStatus.Got)
			assert.Equal(t, filtertest.ServerName, errStatus.ServerName)
		},
	}

	s := newDefault(t, &ruleliststorage.Config{
		ErrColl:      errColl,
		IndexStorage: newRuleListIdxStorage(t, rlIdxURL),
		// Use a smaller staleness value to make sure that the filter is refreshed.
		Staleness: 1 * time.Microsecond,
	})

	// The first refresh, success.
	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	require.True(t, s.HasListID(ctx, filtertest.RuleListID1))

	// The second refresh, not found.  The older version of the rule-list filter
	// must still be used.
	err := s.Refresh(ctx)
	require.NoError(t, err)
	require.True(t, s.HasListID(ctx, filtertest.RuleListID1))
}

func TestDefault_Refresh_updTime(t *testing.T) {
	t.Parallel()

	var (
		origTime = time.Now().Truncate(1 * time.Second)
		modTime  = origTime.Add(time.Hour)
	)

	rlCh := make(chan unit, 1)
	_, ruleListURL := filtertest.PrepareRefreshable(t, rlCh, testFilterData, http.StatusOK)
	ruleListURLStr := ruleListURL.String()

	rlIdxData := errors.Must(json.Marshal(map[string]any{
		"filters": []map[string]any{{
			"filterKey":   filtertest.RuleListID1Str,
			"downloadUrl": ruleListURLStr,
			"timeUpdated": origTime.Format(ruleliststorage.IdxTimeUpdatedFormat),
		}},
	}))

	updIdxData := errors.Must(json.Marshal(map[string]any{
		"filters": []map[string]any{{
			"filterKey":   filtertest.RuleListID1Str,
			"downloadUrl": ruleListURLStr,
			"timeUpdated": modTime.Format(ruleliststorage.IdxTimeUpdatedFormat),
		}},
	}))

	indexDataCh := make(chan []byte, 3)
	indexDataCh <- rlIdxData

	rlIdxURL := newDataServer(t, indexDataCh)
	s := newDefault(t, &ruleliststorage.Config{
		IndexStorage: newRuleListIdxStorage(t, rlIdxURL),
		// Use a smaller staleness value to make sure that the filter is refreshed.
		Staleness: 1 * time.Microsecond,
	})

	// The first refresh, success.
	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	require.True(t, s.HasListID(ctx, filtertest.RuleListID1))
	testutil.RequireReceive(t, rlCh, filtertest.Timeout)

	var rls []*rulelist.Refreshable
	rls = s.AppendForListIDs(ctx, rls, []filter.ID{filtertest.RuleListID1})
	assert.Len(t, rls, 1)

	// The second refresh, filter is not updated.  The older version of the
	// rule-list filter must still be used.
	indexDataCh <- rlIdxData
	err := s.Refresh(ctx)
	require.NoError(t, err)
	require.True(t, s.HasListID(ctx, filtertest.RuleListID1))
	require.Empty(t, rlCh)

	rls = s.AppendForListIDs(ctx, rls[:0], []filter.ID{filtertest.RuleListID1})
	assert.Len(t, rls, 1)

	// The third refresh, filter is updated.  The recent version of the
	// rule-list filter must be used.
	indexDataCh <- updIdxData
	err = s.Refresh(ctx)
	require.NoError(t, err)
	require.True(t, s.HasListID(ctx, filtertest.RuleListID1))
	testutil.RequireReceive(t, rlCh, filtertest.Timeout)

	rls = s.AppendForListIDs(ctx, rls[:0], []filter.ID{filtertest.RuleListID1})
	assert.Len(t, rls, 1)
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

// newDataServer is a helper that creates a server responding with bytes sent
// over dataCh.
func newDataServer(tb testing.TB, dataCh <-chan []byte) (srvURL *url.URL) {
	tb.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		w.Header().Set(httphdr.Server, filtertest.ServerName)
		w.WriteHeader(http.StatusOK)

		data, ok := testutil.RequireReceive(tb, dataCh, filtertest.Timeout)
		require.True(pt, ok)

		_, writeErr := w.Write(data)
		require.NoError(pt, writeErr)
	}))

	tb.Cleanup(srv.Close)

	srvURL, err := agdhttp.ParseHTTPURL(srv.URL)
	require.NoError(tb, err)

	return srvURL
}
