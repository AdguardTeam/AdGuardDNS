package filtertest

import (
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/domain"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
)

// NewDomainFilter is a helper constructor of domain filters for tests.  Sets
// the filter category ID to [CategoryID].
func NewDomainFilter(tb testing.TB, data string) (f *domain.Filter) {
	tb.Helper()

	cachePath, srvURL := PrepareRefreshable(tb, nil, data, http.StatusOK)
	f, err := domain.NewFilter(&domain.FilterConfig{
		Logger:           Logger,
		CacheManager:     agdcache.EmptyManager{},
		URL:              srvURL,
		DomainMetrics:    domain.EmptyMetrics{},
		Metrics:          filter.EmptyMetrics{},
		PublicSuffixList: publicsuffix.List,
		CategoryID:       CategoryID,
		ResultListID:     filter.IDCategory,
		CachePath:        cachePath,
		Staleness:        Staleness,
		CacheTTL:         CacheTTL,
		CacheCount:       CacheCount,
		MaxSize:          FilterMaxSize,
		SubDomainNum:     SubDomainNum,
	})

	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, Timeout)
	require.NoError(tb, f.RefreshInitial(ctx))

	return f
}
