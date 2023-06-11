package websvc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkedIPProxy_ServeHTTP(t *testing.T) {
	var numReq atomic.Uint64
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		pt := testutil.PanicT{}

		rid := r.Header.Get(httphdr.XRequestID)
		require.NotEmpty(pt, rid)

		numReq.Add(1)
	})

	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)

	apiURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	h := linkedIPHandler(
		apiURL,
		&agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) { panic(err) },
		},
		"test",
		2*time.Second,
	)

	expectedUserAgent := agdhttp.UserAgent()

	testCases := []struct {
		name     string
		method   string
		path     string
		diff     uint64
		wantCode int
	}{{
		name:     "linkip",
		method:   http.MethodGet,
		path:     "/linkip/dev1234/0123456789/status",
		diff:     +1,
		wantCode: http.StatusOK,
	}, {
		name:     "ddns",
		method:   http.MethodPost,
		path:     "/ddns/dev1234/0123456789/example.com",
		diff:     +1,
		wantCode: http.StatusOK,
	}, {
		name:     "other",
		method:   http.MethodGet,
		path:     "/some/other/path",
		diff:     0,
		wantCode: http.StatusNotFound,
	}, {
		name:     "robots_txt",
		method:   http.MethodGet,
		path:     "/robots.txt",
		diff:     0,
		wantCode: http.StatusOK,
	}, {
		name:     "linkip_bad_path",
		method:   http.MethodGet,
		path:     "/linkip/dev1234/0123456789/status/more/stuff",
		diff:     0,
		wantCode: http.StatusNotFound,
	}, {
		name:     "linkip_bad_method",
		method:   http.MethodDelete,
		path:     "/linkip/dev1234/0123456789/status",
		diff:     0,
		wantCode: http.StatusNotFound,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, (&url.URL{
				Scheme: "http",
				Host:   "www.example.com",
				Path:   tc.path,
			}).String(), strings.NewReader(""))
			rw := httptest.NewRecorder()

			prev := numReq.Load()
			h.ServeHTTP(rw, r)
			assert.Equal(t, prev+tc.diff, numReq.Load(), "req was not expected")

			assert.Equal(t, tc.wantCode, rw.Code)
			assert.Equal(t, expectedUserAgent, rw.Header().Get(httphdr.Server))
		})
	}
}
