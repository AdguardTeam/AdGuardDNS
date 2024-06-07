package websvc_test

import (
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

func TestService_ServeHTTP_static(t *testing.T) {
	staticContent := map[string]*websvc.StaticFile{
		"/favicon.ico": {
			Content: []byte{},
			Headers: http.Header{
				httphdr.ContentType: []string{"image/x-icon"},
			},
		},
	}

	c := &websvc.Config{
		StaticContent: staticContent,
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
		httphdr.Server:      []string{"AdGuardDNS/"},
	}
	assertResponseWithHeaders(t, svc, "/favicon.ico", http.StatusOK, respHdr)
}
