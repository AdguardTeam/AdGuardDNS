package ruleliststorage_test

import (
	"cmp"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/ruleliststorage"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/require"
)

// testFilterData is the content for filter in the test index.
const testFilterData = filtertest.RuleBlockStr + "\n"

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
	c.IndexConfig = cmp.Or(c.IndexConfig, newIndexConfig(&url.URL{}))
	c.Logger = cmp.Or(c.Logger, filtertest.Logger)
	c.Metrics = cmp.Or[filter.Metrics](c.Metrics, filter.EmptyMetrics{})

	s, err := ruleliststorage.New(c)
	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)

	err = s.RefreshInitial(ctx)
	require.NoError(tb, err)

	return s
}

// newIndexConfig is a test helper that returns a new *IndexConfig with the
// given index URL.  The rest of the fields are set to the corresponding
// [filtertest] values.
func newIndexConfig(indexURL *url.URL) (c *ruleliststorage.IndexConfig) {
	return &ruleliststorage.IndexConfig{
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
