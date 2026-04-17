package debugsvc_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_Start_cacheAPI(t *testing.T) {
	t.Parallel()

	const successResp = `{"results":{"` + testRefresherID + `":"ok"}}`

	cacheManager := agdcache.NewDefaultManager()
	cacheManager.Add("test", agdcache.Empty[any, any]{})

	c := &debugsvc.Config{
		APIAddr: localhostAnyPort,
		Manager: cacheManager,
	}

	svc := newTestDebugService(t, c)
	servicetest.RequireRun(t, svc, testTimeout)

	srvAddr := requireHandlerGroupAddr(t, svc, debugsvc.HandlerGroupAPI)

	client := &http.Client{
		Timeout: testTimeout,
	}

	srvURL := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   srvAddr.String(),
	}

	// First check health-check service URL.  As the service could not be ready
	// yet, check for it in periodically.
	eventuallyCheckHealth(t, client, srvURL)

	cacheURL := srvURL.JoinPath(debugsvc.PathPatternDebugAPICache)

	cacheURLStr := cacheURL.String()

	testCases := []struct {
		name     string
		reqBody  string
		wantResp string
	}{{
		name:     "success",
		reqBody:  `{"ids":["` + testRefresherID + `"]}`,
		wantResp: successResp,
	}, {
		name:     "success_all",
		reqBody:  `{"ids":["*"]}`,
		wantResp: successResp,
	}, {
		name:     "empty_ids",
		reqBody:  `{"ids":[""]}`,
		wantResp: `{"results":{}}`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reqBody := strings.NewReader(tc.reqBody)
			resp, err := client.Post(cacheURLStr, agdhttp.HdrValApplicationJSON, reqBody)
			require.NoError(t, err)

			respBody := readRespBody(t, resp)
			assert.JSONEq(t, tc.wantResp, respBody)
		})
	}
}
