package websvc_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_ServeHTTP(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := io.WriteString(w, "[]")
		require.NoError(pt, err)
	})

	rootRedirectURL := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "adguard-dns.com",
		Path:   "/",
	}

	c := &websvc.Config{
		RootRedirectURL: rootRedirectURL,
		StaticContent:   http.NotFoundHandler(),
		DNSCheck:        mockHandler,
	}

	svc := websvc.New(c)
	require.NotNil(t, svc)

	var err error
	require.NotPanics(t, func() {
		err = svc.Start(testutil.ContextWithTimeout(t, testTimeout))
	})
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})

	// DNSCheck path.
	assertResponse(t, svc, "/dnscheck/test", http.StatusOK)

	// Robots path.
	assertResponse(t, svc, "/robots.txt", http.StatusOK)

	// Root redirect path.
	assertResponse(t, svc, "/", http.StatusFound)

	// Other path.
	assertResponse(t, svc, "/other", http.StatusNotFound)
}

// assertResponse is a helper function that checks status code of HTTP
// response.
func assertResponse(
	t *testing.T,
	svc *websvc.Service,
	path string,
	statusCode int,
) (rw *httptest.ResponseRecorder) {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, (&url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "127.0.0.1",
		Path:   path,
	}).String(), strings.NewReader(""))

	rw = httptest.NewRecorder()
	svc.ServeHTTP(rw, r)

	assert.Equal(t, statusCode, rw.Code)
	assert.Equal(t, agdhttp.UserAgent(), rw.Header().Get(httphdr.Server))

	return rw
}

// assertResponseWithHeaders is a helper function that checks status code and
// headers of HTTP response.
func assertResponseWithHeaders(
	t *testing.T,
	svc *websvc.Service,
	path string,
	statusCode int,
	respHdr http.Header,
) {
	t.Helper()

	rw := assertResponse(t, svc, path, statusCode)

	assert.Equal(t, respHdr, rw.Header())
}
