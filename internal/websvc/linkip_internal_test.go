package websvc

import (
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
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkedIPProxy_ServeHTTP(t *testing.T) {
	var (
		apiURL *url.URL
		numReq atomic.Uint64
	)

	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		pt := testutil.PanicT{}

		hdr := r.Header

		require.Equal(pt, agdhttp.UserAgent(), hdr.Get(httphdr.UserAgent))
		require.NotEmpty(pt, hdr.Get(httphdr.XConnectingIP))
		require.NotEmpty(pt, hdr.Get(httphdr.XRequestID))

		require.Empty(pt, hdr.Get(httphdr.CFConnectingIP))
		require.Empty(pt, hdr.Get(httphdr.Forwarded))
		require.Empty(pt, hdr.Get(httphdr.TrueClientIP))
		require.Empty(pt, hdr.Get(httphdr.XForwardedFor))
		require.Empty(pt, hdr.Get(httphdr.XForwardedHost))
		require.Empty(pt, hdr.Get(httphdr.XForwardedProto))
		require.Empty(pt, hdr.Get(httphdr.XRealIP))

		require.Equal(pt, apiURL.Host, r.Host)

		numReq.Add(1)
	})

	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)

	apiURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	h := linkedIPHandler(apiURL, agdtest.NewErrorCollector(), "test", 2*time.Second)

	testCases := []struct {
		name                    string
		method                  string
		path                    string
		wantAccessControlHdrVal string
		diff                    uint64
		wantCode                int
	}{{
		name:                    "linkip",
		method:                  http.MethodGet,
		path:                    "/linkip/dev1234/0123456789/status",
		diff:                    +1,
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: agdhttp.HdrValWildcard,
	}, {
		name:                    "ddns",
		method:                  http.MethodPost,
		path:                    "/ddns/dev1234/0123456789/example.com",
		diff:                    +1,
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: agdhttp.HdrValWildcard,
	}, {
		name:                    "other",
		method:                  http.MethodGet,
		path:                    "/some/other/path",
		diff:                    0,
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}, {
		name:                    "robots_txt",
		method:                  http.MethodGet,
		path:                    "/robots.txt",
		diff:                    0,
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: "",
	}, {
		name:                    "linkip_bad_path",
		method:                  http.MethodGet,
		path:                    "/linkip/dev1234/0123456789/status/more/stuff",
		diff:                    0,
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}, {
		name:                    "linkip_bad_method",
		method:                  http.MethodDelete,
		path:                    "/linkip/dev1234/0123456789/status",
		diff:                    0,
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, (&url.URL{
				Scheme: urlutil.SchemeHTTP,
				Host:   "link-ip.example",
				Path:   tc.path,
			}).String(), strings.NewReader(""))

			// Set some test headers.
			r.Header.Set(httphdr.CFConnectingIP, "1.1.1.1")
			r.Header.Set(httphdr.Forwarded, "1.1.1.1")
			r.Header.Set(httphdr.TrueClientIP, "1.1.1.1")
			r.Header.Set(httphdr.XForwardedFor, "1.1.1.1")
			r.Header.Set(httphdr.XForwardedHost, "forward.example")
			r.Header.Set(httphdr.XForwardedProto, "https")
			r.Header.Set(httphdr.XRealIP, "1.1.1.1")

			rw := httptest.NewRecorder()

			prev := numReq.Load()
			h.ServeHTTP(rw, r)
			assert.Equal(t, prev+tc.diff, numReq.Load(), "req was not expected")
			assert.Equal(t, tc.wantCode, rw.Code)

			hdr := rw.Header()
			assert.Equal(t, agdhttp.UserAgent(), hdr.Get(httphdr.Server))
			assert.Equal(t, tc.wantAccessControlHdrVal, hdr.Get(httphdr.AccessControlAllowOrigin))
		})
	}
}
