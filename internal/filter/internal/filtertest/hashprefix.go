package filtertest

import (
	"context"
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

// NewHashprefixFilter is like [NewHashprefixFilterWithRepl], but the
// replacement host is also set in accordance with id.
func NewHashprefixFilter(tb testing.TB, id internal.ID) (f *hashprefix.Filter) {
	tb.Helper()

	var replHost string
	switch id {
	case internal.IDAdultBlocking:
		replHost = HostAdultContentRepl
	case internal.IDNewRegDomains:
		replHost = HostNewlyRegisteredRepl
	case internal.IDSafeBrowsing:
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
	id internal.ID,
	replHost string,
) (f *hashprefix.Filter) {
	tb.Helper()

	var data string
	switch id {
	case internal.IDAdultBlocking:
		data = HostAdultContent + "\n"
	case internal.IDNewRegDomains:
		data = HostNewlyRegistered + "\n"
	case internal.IDSafeBrowsing:
		data = HostDangerous + "\n"
	default:
		tb.Fatalf("bad id: %q", id)
	}

	cachePath, srvURL := PrepareRefreshable(tb, nil, data, http.StatusOK)

	strg, err := hashprefix.NewStorage("")
	require.NoError(tb, err)

	f, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger: slogutil.NewDiscardLogger(),
		// TODO(a.garipov):  Use [agdtest.NewCloner] when the import cycle is
		// resolved.
		Cloner:       dnsmsg.NewCloner(dnsmsg.EmptyClonerStat{}),
		CacheManager: agdcache.EmptyManager{},
		Hashes:       strg,
		URL:          srvURL,
		// TODO(a.garipov):  Use [agdtest.NewErrorCollector] when the import
		// cycle is resolved.
		ErrColl:         errColl{},
		Metrics:         internal.EmptyMetrics{},
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
