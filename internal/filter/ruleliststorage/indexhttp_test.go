package ruleliststorage_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/ruleliststorage"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

func TestIndexHTTP(t *testing.T) {
	t.Parallel()

	f := ruleliststorage.NewIndexHTTP(&ruleliststorage.IndexHTTPConfig{
		Logger:  filtertest.Logger,
		ErrColl: agdtest.NewErrorCollector(),
		URL:     newServer(t, newIndexData(t)),
		Timeout: filtertest.Timeout,
		MaxSize: filtertest.FilterMaxSize,
	})

	assertIndexData(t, f)
}

// newServer starts a new [*httptest.Server] that serves the given data and
// returns its URL.  The server is closed on clean up.
func newServer(tb testing.TB, data []byte) (srvURL *url.URL) {
	tb.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		w.Header().Set(httphdr.Server, filtertest.ServerName)
		w.WriteHeader(http.StatusOK)

		_, writeErr := w.Write(data)
		require.NoError(pt, writeErr)
	}))
	tb.Cleanup(srv.Close)

	srvURL, err := agdhttp.ParseHTTPURL(srv.URL)
	require.NoError(tb, err)

	return srvURL
}
