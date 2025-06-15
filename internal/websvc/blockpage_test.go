package websvc_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// blockPageFileName is the name of test block page content file.
	blockPageFileName = "block_page.html"

	// blockPageContent is the content of test block page file.
	blockPageContent = "<html><body>Block page</body></html>\n"
)

func TestBlockPageServers(t *testing.T) {
	t.Parallel()

	robotsContent := []byte(agdhttp.RobotsDisallowAll)

	const (
		contentStatus = http.StatusInternalServerError
		faviconStatus = http.StatusNotFound
		robotsStatus  = http.StatusOK
	)

	bps := &websvc.BlockPageServerConfig{
		ContentFilePath: filepath.Join("testdata", blockPageFileName),
		Bind: []*websvc.BindData{{
			TLS:     nil,
			Address: localhostZeroPort,
		}},
	}

	conf := &websvc.Config{
		Logger:               testLogger,
		CertificateValidator: testCertValidator,
		StaticContent:        http.NotFoundHandler(),
		DNSCheck:             http.NotFoundHandler(),
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              websvc.EmptyMetrics{},
		Timeout:              testTimeout,
		AdultBlocking:        bps,
		GeneralBlocking:      bps,
		SafeBrowsing:         bps,
	}

	svc := websvc.New(conf)
	startService(t, svc)

	testCases := []struct {
		name        string
		serverGroup websvc.ServerGroup
	}{{
		name:        "adult_blocking",
		serverGroup: websvc.ServerGroupAdultBlockingPage,
	}, {
		name:        "general_blocking",
		serverGroup: websvc.ServerGroupGeneralBlockingPage,
	}, {
		name:        "safe_browsing",
		serverGroup: websvc.ServerGroupSafeBrowsingPage,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr := requireServerGroupAddr(t, svc, tc.serverGroup)
			a := addr.AddrPort()

			assertContent(t, a, "/", contentStatus, []byte(blockPageContent))
			assertContent(t, a, "/favicon.ico", faviconStatus, []byte(agdhttp.NotFoundString))
			assertContent(t, a, "/robots.txt", robotsStatus, robotsContent)
		})
	}
}

func TestBlockPageServers_noBlockPages(t *testing.T) {
	t.Parallel()

	conf := &websvc.Config{
		Logger:               testLogger,
		CertificateValidator: testCertValidator,
		StaticContent:        http.NotFoundHandler(),
		DNSCheck:             http.NotFoundHandler(),
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              websvc.EmptyMetrics{},
		Timeout:              testTimeout,
	}

	svc := websvc.New(conf)
	require.NotNil(t, svc)

	require.NotPanics(t, func() {
		assert.NoError(t, svc.Start(testutil.ContextWithTimeout(t, testTimeout)))
		assert.NoError(t, svc.Shutdown(testutil.ContextWithTimeout(t, testTimeout)))
	})
}

func TestBlockPageServers_gzip(t *testing.T) {
	t.Parallel()

	bps := &websvc.BlockPageServerConfig{
		ContentFilePath: filepath.Join("testdata", blockPageFileName),
		Bind: []*websvc.BindData{{
			TLS:     nil,
			Address: localhostZeroPort,
		}},
	}

	conf := &websvc.Config{
		Logger:               testLogger,
		GeneralBlocking:      bps,
		CertificateValidator: testCertValidator,
		StaticContent:        http.NotFoundHandler(),
		DNSCheck:             http.NotFoundHandler(),
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              websvc.EmptyMetrics{},
		Timeout:              testTimeout,
	}

	svc := websvc.New(conf)
	startService(t, svc)

	addr := requireServerGroupAddr(t, svc, websvc.ServerGroupGeneralBlockingPage)

	cl := http.Client{
		Timeout: testTimeout,
	}

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	u := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   addr.String(),
		Path:   "/",
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	require.NoError(t, err)

	req.Header.Set(httphdr.AcceptEncoding, agdhttp.HdrValGzip)

	resp, err := cl.Do(req)
	require.NoError(t, err)

	zr, err := gzip.NewReader(resp.Body)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, zr.Close)

	body, err := io.ReadAll(zr)
	require.NoError(t, err)

	assert.Equal(t, []byte(blockPageContent), body)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, agdhttp.UserAgent(), resp.Header.Get(httphdr.Server))
	assert.Equal(t, agdhttp.HdrValGzip, resp.Header.Get(httphdr.ContentEncoding))
}
