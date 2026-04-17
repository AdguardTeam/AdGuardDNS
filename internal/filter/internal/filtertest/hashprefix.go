package filtertest

import (
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
)

// SubDomainNum is a common subDomainNum value for tests.
const SubDomainNum = 4

// NewHashprefixFilter is like [NewHashprefixFilterWithRepl], but the
// replacement host is also set in accordance with id.
func NewHashprefixFilter(tb testing.TB, id filter.ID) (f *hashprefix.Filter) {
	tb.Helper()

	var replHost string
	switch id {
	case filter.IDAdultBlocking:
		replHost = HostAdultContentRepl
	case filter.IDNewRegDomains:
		replHost = HostNewlyRegisteredRepl
	case filter.IDSafeBrowsing:
		replHost = HostDangerousRepl
	default:
		tb.Fatalf("bad id: %q", id)
	}

	return NewHashprefixFilterWithRepl(tb, id, replHost)
}

// NewHashprefixFilterWithRepl is a helper constructor of hashprefix filters for
// tests.  The hash data is set in accordance with id.
func NewHashprefixFilterWithRepl(
	tb testing.TB,
	id filter.ID,
	replHost string,
) (f *hashprefix.Filter) {
	tb.Helper()

	var data string
	switch id {
	case filter.IDAdultBlocking:
		data = HostAdultContent + "\n"
	case filter.IDNewRegDomains:
		data = HostNewlyRegistered + "\n"
	case filter.IDSafeBrowsing:
		data = HostDangerous + "\n"
	default:
		tb.Fatalf("bad id: %q", id)
	}

	cachePath, srvURL := PrepareRefreshable(tb, nil, data, http.StatusOK)

	strg, err := hashprefix.NewStorage(nil)
	require.NoError(tb, err)

	cloner := agdtest.NewCloner()
	replCons, err := filter.NewReplacedResultConstructor(&filter.ReplacedResultConstructorConfig{
		Cloner:      cloner,
		Replacement: replHost,
	})
	require.NoError(tb, err)

	f, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:                    Logger,
		Cloner:                    cloner,
		CacheManager:              agdcache.EmptyManager{},
		Hashes:                    strg,
		ReplacedResultConstructor: replCons,
		URL:                       srvURL,
		ErrColl:                   agdtest.NewErrorCollector(),
		HashPrefixMetrics:         hashprefix.EmptyMetrics{},
		Metrics:                   filter.EmptyMetrics{},
		PublicSuffixList:          publicsuffix.List,
		ID:                        id,
		CachePath:                 cachePath,
		Staleness:                 Staleness,
		CacheTTL:                  CacheTTL,
		CacheCount:                CacheCount,
		MaxSize:                   FilterMaxSize,
		SubDomainNum:              SubDomainNum,
	})
	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, Timeout)
	require.NoError(tb, f.RefreshInitial(ctx))

	return f
}
