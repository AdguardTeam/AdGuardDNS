package websvc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_ServeHTTP(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := w.Write([]byte("[]"))
		require.NoError(pt, err)
	})

	rootRedirectURL := &url.URL{
		Scheme: "http",
		Host:   "adguard-dns.com",
		Path:   "/",
	}

	staticContent := map[string]*websvc.StaticFile{
		"/favicon.ico": {
			ContentType: "image/x-icon",
			Content:     []byte{},
		},
	}

	c := &websvc.Config{
		RootRedirectURL: rootRedirectURL,
		StaticContent:   staticContent,
		DNSCheck:        mockHandler,
	}

	svc := websvc.New(c)
	require.NotNil(t, svc)

	var err error
	require.NotPanics(t, func() {
		err = svc.Start()
	})
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(context.Background())
	})

	// DNSCheck path.
	assertPathResponse(t, svc, "/dnscheck/test", http.StatusOK)

	// Static content path.
	assertPathResponse(t, svc, "/favicon.ico", http.StatusOK)

	// Robots path.
	assertPathResponse(t, svc, "/robots.txt", http.StatusOK)

	// Root redirect path.
	assertPathResponse(t, svc, "/", http.StatusFound)

	// Other path.
	assertPathResponse(t, svc, "/other", http.StatusNotFound)
}

func assertPathResponse(t *testing.T, svc *websvc.Service, path string, statusCode int) {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, (&url.URL{
		Scheme: "http",
		Host:   "127.0.0.1",
		Path:   path,
	}).String(), strings.NewReader(""))
	rw := httptest.NewRecorder()
	svc.ServeHTTP(rw, r)

	assert.Equal(t, statusCode, rw.Code)
	assert.Equal(t, agdhttp.UserAgent(), rw.Header().Get(agdhttp.HdrNameServer))
}
