package websvc_test

import (
	"io"
	"net"
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
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// testCertValidator is the common certificate validator for tests.
var testCertValidator = websvc.RejectCertificateValidator{}

// localhostZeroPort is a common used default host and dynamic port.
var localhostZeroPort = netip.AddrPortFrom(netutil.IPv4Localhost(), 0)

func TestNew(t *testing.T) {
	t.Parallel()

	c := &websvc.Config{
		Logger:               testLogger,
		CertificateValidator: testCertValidator,
		StaticContent:        http.NotFoundHandler(),
		DNSCheck:             http.NotFoundHandler(),
		ErrColl:              agdtest.NewErrorCollector(),
		Timeout:              testTimeout,
	}

	svc := websvc.New(c)
	startService(t, svc)
}

func TestService_NonDoH(t *testing.T) {
	t.Parallel()

	robotsContent := []byte(agdhttp.RobotsDisallowAll)

	content := []byte("content")
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := w.Write(content)
		require.NoError(pt, err)
	})

	nonDoHBind := []*websvc.BindData{{
		TLS:     nil,
		Address: localhostZeroPort,
	}}

	notFoundContent := []byte("not found")
	c := &websvc.Config{
		Logger:               testLogger,
		CertificateValidator: testCertValidator,
		StaticContent:        http.NotFoundHandler(),
		DNSCheck:             mockHandler,
		NonDoHBind:           nonDoHBind,
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              websvc.EmptyMetrics{},
		Error404:             notFoundContent,
		Timeout:              testTimeout,
	}

	svc := websvc.New(c)
	startService(t, svc)

	addr := requireServerGroupAddr(t, svc, websvc.ServerGroupNonDoH)
	a := addr.AddrPort()

	assertContent(t, a, "/dnscheck/test", http.StatusOK, content)
	assertContent(t, a, "/robots.txt", http.StatusOK, robotsContent)

	client := http.Client{
		Timeout: testTimeout,
	}

	resp, err := client.Get((&url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   a.String(),
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

	cl := http.Client{
		Timeout: testTimeout,
	}

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	u := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   addr.String(),
		Path:   path,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	require.NoError(t, err)

	resp, err := cl.Do(req)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, expected, body)
	assert.Equal(t, status, resp.StatusCode)
	assert.Equal(t, agdhttp.UserAgent(), resp.Header.Get(httphdr.Server))
}

// startService starts and validates an existed instance of [*websvc.Service].
func startService(t *testing.T, svc *websvc.Service) {
	t.Helper()

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

// requireServerGroupAddr is a helper function that waits for [*websvc.Service]
// instance getting address(es), validates the 1st one and returns it. It uses
// EventuallyWithT with global testTimeout as duration.
func requireServerGroupAddr(
	t *testing.T,
	svc *websvc.Service,
	sg websvc.ServerGroup,
) (addr *net.TCPAddr) {
	t.Helper()

	var addrs []net.Addr
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		addrs = svc.LocalAddrs(sg)
		require.NotEmpty(c, addrs)
		require.NotNil(c, addrs[0])
	}, testTimeout, testTimeout/10)

	return testutil.RequireTypeAssert[*net.TCPAddr](t, addrs[0])
}
