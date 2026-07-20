package ruleliststorage_test

import (
	"cmp"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/ruleliststorage"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testFilterData is the content for filter in the test index.
const testFilterData = filtertest.RuleBlockStr + "\n"

var (
	// filterDownloadURL is the URL for filter tests.
	filterDownloadURL = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "example.test",
		Path:   "/filter",
	}

	// filterUpdTime is the update time for filter tests.
	filterUpdTime = time.Date(2026, time.June, 1, 14, 30, 0, 0, &time.Location{})

	// filterUpdTimeStr is filterUpdTime formatted as a string for the test
	// index data.
	filterUpdTimeStr = filterUpdTime.Format(ruleliststorage.IdxTimeUpdatedFormat)
)

// newIndexData returns the index data for tests.  The returned data corresponds
// to an index with one custom filter with ID [filtertest.RuleListIDCustom],
// download URL filterDownloadURL, and update time filterUpdTime.
func newIndexData(tb testing.TB) (data []byte) {
	tb.Helper()

	return errors.Must(json.Marshal(map[string]any{
		"filters": []map[string]any{{
			"filterKey":   filtertest.RuleListIDCustomStr,
			"downloadUrl": filterDownloadURL.String(),
			"timeUpdated": filterUpdTimeStr,
		}},
	}))
}

// assertIndexData asserts that the rule list index data returned by the given
// storage corresponds to the index data returned by newIndexData.
func assertIndexData(tb testing.TB, storage filterindex.RulelistStorage) {
	tb.Helper()

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)
	got, err := storage.Rulelist(ctx)
	require.NoError(tb, err)
	require.NotNil(tb, got)

	filters := got.Filters
	assert.Len(tb, filters, 1)

	require.Contains(tb, filters, filtertest.RuleListIDCustom)

	flt := filters[filtertest.RuleListIDCustom]
	assert.Equal(tb, filterDownloadURL, flt.DownloadURL)
	assert.True(tb, filterUpdTime.Equal(flt.UpdateTime))
	assert.True(tb, flt.IsCustom)
}

// newDefault is a helper for creating the rule list storage for tests.  c may
// be nil, and all zero-value fields in c are replaced with defaults for tests.
func newDefault(tb testing.TB, c *ruleliststorage.Config) (s *ruleliststorage.Default) {
	tb.Helper()

	c = cmp.Or(c, &ruleliststorage.Config{})
	c.CacheDir = cmp.Or(c.CacheDir, tb.TempDir())
	filtertest.CreateFilterCacheDirs(tb, c.CacheDir)

	c.BaseLogger = cmp.Or(c.BaseLogger, filtertest.Logger)
	c.CacheManager = cmp.Or[agdcache.Manager](c.CacheManager, agdcache.EmptyManager{})
	c.Clock = cmp.Or[timeutil.Clock](c.Clock, timeutil.SystemClock{})
	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, agdtest.NewErrorCollector())
	c.IndexStorage = cmp.Or[filterindex.RulelistStorage](
		c.IndexStorage,
		filterindex.EmptyRulelistStorage{},
	)
	c.Logger = cmp.Or(c.Logger, filtertest.Logger)
	c.Metrics = cmp.Or[filter.Metrics](c.Metrics, filter.EmptyMetrics{})
	c.MaxSize = cmp.Or(c.MaxSize, filtertest.FilterMaxSize)
	c.RefreshTimeout = cmp.Or(c.RefreshTimeout, filtertest.Timeout)
	c.Staleness = cmp.Or(c.Staleness, filtertest.Staleness)
	c.ResultCacheCount = cmp.Or(c.ResultCacheCount, filtertest.CacheCount)

	s, err := ruleliststorage.New(c)
	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)

	err = s.RefreshInitial(ctx)
	require.NoError(tb, err)

	return s
}

// newRuleListIdxStorage is a test helper that returns a new
// [filterindex.RulelistStorage] for the given index URL.  indexURL must not be
// nil.
func newRuleListIdxStorage(tb testing.TB, indexURL *url.URL) (s filterindex.RulelistStorage) {
	tb.Helper()

	return ruleliststorage.NewIndexHTTP(&ruleliststorage.IndexHTTPConfig{
		Logger:  slogutil.NewDiscardLogger(),
		ErrColl: agdtest.NewErrorCollector(),
		URL:     indexURL,
		Timeout: filtertest.Timeout,
		MaxSize: filtertest.FilterMaxSize,
	})
}
