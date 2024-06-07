package websvc_test

import (
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTimeout = 1 * time.Second

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

func TestNew(t *testing.T) {
	startService(t, &websvc.Config{})
}

func TestService_NonDoH(t *testing.T) {
	robotsContent := []byte(agdhttp.RobotsDisallowAll)

	content := []byte("content")
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := w.Write(content)
		require.NoError(pt, err)
	})

	nonDoHPort := netip.MustParseAddrPort("127.0.0.1:3003")
	nonDoHBind := []*websvc.BindData{{
		TLS:     nil,
		Address: nonDoHPort,
	}}

	notFoundContent := []byte("not found")
	c := &websvc.Config{
		DNSCheck:   mockHandler,
		NonDoHBind: nonDoHBind,
		Error404:   notFoundContent,
		Timeout:    testTimeout,
	}

	startService(t, c)

	assertContent(t, nonDoHPort, "/dnscheck/test", http.StatusOK, content)
	assertContent(t, nonDoHPort, "/robots.txt", http.StatusOK, robotsContent)

	client := http.Client{
		Timeout: testTimeout,
	}

	resp, err := client.Get((&url.URL{
		Scheme: "http",
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
		Scheme: "http",
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
		err = svc.Start(testutil.ContextWithTimeout(t, testTimeout))
	})
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})
}
