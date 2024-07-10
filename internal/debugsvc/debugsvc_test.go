package debugsvc_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(a.garipov): Improve and split tests.

// testTimeout is a common timeout for tests.
const testTimeout = 1 * time.Second

func TestService_Start(t *testing.T) {
	// TODO(a.garipov): Consider adding an HTTP server constructor as a part of
	// the configuration structure to use net/http/httptest's server in tests.
	const addr = "127.0.0.1:8082"
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := w.Write([]byte("[]"))
		require.NoError(pt, err)
	})

	refreshed := false
	c := &debugsvc.Config{
		Logger:       slogutil.NewDiscardLogger(),
		DNSDBAddr:    addr,
		DNSDBHandler: h,
		Refreshers: debugsvc.Refreshers{
			"test": &agdtest.Refresher{
				OnRefresh: func(_ context.Context) (err error) {
					refreshed = true

					return nil
				},
			},
		},
		APIAddr:        addr,
		PprofAddr:      addr,
		PrometheusAddr: addr,
	}

	svc := debugsvc.New(c)
	require.NotNil(t, svc)

	var err error
	require.NotPanics(t, func() {
		err = svc.Start(testutil.ContextWithTimeout(t, testTimeout))
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})

	client := http.Client{
		Timeout: 2 * time.Second,
	}

	var resp *http.Response
	var body []byte

	// First check health-check service URL.  As the service could not be ready
	// yet, check for it in periodically.
	require.Eventually(t, func() bool {
		resp, err = client.Get(fmt.Sprintf("http://%s/health-check", addr))
		return err == nil
	}, 1*time.Second, 100*time.Millisecond)

	body = readRespBody(t, resp)
	assert.Equal(t, []byte("OK\n"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check pprof service URL.
	resp, err = client.Get(fmt.Sprintf("http://%s/debug/pprof/", addr))
	require.NoError(t, err)

	body = readRespBody(t, resp)
	assert.True(t, len(body) > 0)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check prometheus service URL.
	resp, err = client.Get(fmt.Sprintf("http://%s/metrics", addr))
	require.NoError(t, err)

	body = readRespBody(t, resp)
	assert.True(t, len(body) > 0)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check refresh API.
	reqBody := strings.NewReader(`{"ids":["test"]}`)
	urlStr := fmt.Sprintf("http://%s/debug/api/refresh", addr)
	resp, err = client.Post(urlStr, "application/json", reqBody)
	require.NoError(t, err)

	assert.True(t, refreshed)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body = readRespBody(t, resp)
	assert.Equal(t, []byte(`{"results":{"test":"ok"}}`+"\n"), body)
}

// readRespBody is a helper function that reads and returns
// body from response.
func readRespBody(t testing.TB, resp *http.Response) (body []byte) {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return body
}
