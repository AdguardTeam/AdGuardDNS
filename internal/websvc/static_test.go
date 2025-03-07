package websvc_test

import (
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_ServeHTTP_static(t *testing.T) {
	staticContent := websvc.StaticContent{
		"/favicon.ico": {
			Content: []byte{},
			Headers: http.Header{
				httphdr.ContentType: []string{"image/x-icon"},
			},
		},
	}

	c := &websvc.Config{
		Logger:        testLogger,
		StaticContent: staticContent,
		DNSCheck:      http.NotFoundHandler(),
		ErrColl:       agdtest.NewErrorCollector(),
		Timeout:       testTimeout,
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

	respHdr := http.Header{
		httphdr.ContentType: []string{"image/x-icon"},
	}
	assertResponseWithHeaders(t, svc, "/favicon.ico", http.StatusOK, respHdr)
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
