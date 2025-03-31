package websvc_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

func TestNew(t *testing.T) {
	startService(t, &websvc.Config{
		Logger:        testLogger,
		StaticContent: http.NotFoundHandler(),
		DNSCheck:      http.NotFoundHandler(),
		ErrColl:       agdtest.NewErrorCollector(),
		Timeout:       testTimeout,
	})
}

func TestService_NonDoH(t *testing.T) {
	robotsContent := []byte(agdhttp.RobotsDisallowAll)

	content := []byte("content")
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := w.Write(content)
		require.NoError(pt, err)
	})

	// TODO(a.garipov):  Do not use hardcoded ports.
	nonDoHPort := netip.MustParseAddrPort("127.0.0.1:3003")
	nonDoHBind := []*websvc.BindData{{
		TLS:     nil,
		Address: nonDoHPort,
	}}

	notFoundContent := []byte("not found")
	c := &websvc.Config{
		Logger:        testLogger,
		StaticContent: http.NotFoundHandler(),
		DNSCheck:      mockHandler,
		NonDoHBind:    nonDoHBind,
		ErrColl:       agdtest.NewErrorCollector(),
		Error404:      notFoundContent,
		Timeout:       testTimeout,
	}

	startService(t, c)

	assertContent(t, nonDoHPort, "/dnscheck/test", http.StatusOK, content)
	assertContent(t, nonDoHPort, "/robots.txt", http.StatusOK, robotsContent)

	client := http.Client{
		Timeout: testTimeout,
	}

	resp, err := client.Get((&url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   nonDoHPort.String(),
		Path:   "/other",
	}).String())
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, notFoundContent, body)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// assertContent performs an HTTP GET request on the given address and port on
// the given path and asserts that the status and content are as expected.
func assertContent(t *testing.T, addr netip.AddrPort, path string, status int, expected []byte) {
	t.Helper()

	c := http.Client{
		Timeout: testTimeout,
	}

	var resp *http.Response
	var err error
	var body []byte

	u := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   addr.String(),
		Path:   path,
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(t, err)

	// First check health-check service URL.  As the service could not be ready
	// yet, check for it periodically.
	require.Eventually(t, func() (ok bool) {
		resp, err = c.Do(req)

		return err == nil
	}, testTimeout, testTimeout/10)

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, expected, body)
	assert.Equal(t, status, resp.StatusCode)
	assert.Equal(t, agdhttp.UserAgent(), resp.Header.Get(httphdr.Server))
}

// startService creates and starts an instance of [*websvc.Service] from the
// provided configuration.
func startService(t *testing.T, c *websvc.Config) {
	t.Helper()

	svc := websvc.New(c)
	require.NotNil(t, svc)

	var err error
	require.NotPanics(t, func() {
		err = svc.Refresh(testutil.ContextWithTimeout(t, testTimeout))
	})
	require.NoError(t, err)

	require.NotPanics(t, func() {
		err = svc.Start(testutil.ContextWithTimeout(t, testTimeout))
	})
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})
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

	return rw
}
