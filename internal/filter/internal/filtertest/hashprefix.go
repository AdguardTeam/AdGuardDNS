package filtertest

import (
	"context"
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

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

	strg, err := hashprefix.NewStorage("")
	require.NoError(tb, err)

	f, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          slogutil.NewDiscardLogger(),
		Cloner:          agdtest.NewCloner(),
		CacheManager:    agdcache.EmptyManager{},
		Hashes:          strg,
		URL:             srvURL,
		ErrColl:         agdtest.NewErrorCollector(),
		HashPrefixMtcs:  hashprefix.EmptyMetrics{},
		Metrics:         filter.EmptyMetrics{},
		ID:              id,
		CachePath:       cachePath,
		ReplacementHost: replHost,
		Staleness:       Staleness,
		CacheTTL:        CacheTTL,
		CacheCount:      CacheCount,
		MaxSize:         FilterMaxSize,
	})
	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, Timeout)
	require.NoError(tb, f.RefreshInitial(ctx))

	return f
}

// errColl is a panicking error collector for filter tests.  It should be
// replaced with [agdtest.NewErrorCollector] when the import cycle is resolved.
type errColl struct{}

// type check
var _ errcoll.Interface = errColl{}

// Collect implements the [errcoll.Interface] for errColl.
func (errColl) Collect(ctx context.Context, err error) { panic(err) }
