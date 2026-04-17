package debugsvc_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakeservice"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test refresher IDs.
const (
	testRefresherID             = "test"
	testRefresherIDParentFirst  = "parent/first"
	testRefresherIDParentSecond = "parent/second"
)

func TestService_Start_refreshAPI(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		reqBody        string
		wantResp       string
		wantRefreshers []string
	}{{
		name:           "success_single_refresher",
		reqBody:        `{"ids":["` + testRefresherID + `"]}`,
		wantResp:       `{"results":{"` + testRefresherID + `":"ok"}}`,
		wantRefreshers: []string{testRefresherID},
	}, {
		name:    "success_parent_refreshers",
		reqBody: `{"ids":["parent/*"]}`,
		wantResp: `{"results":{"` + testRefresherIDParentFirst + `":"ok","` +
			testRefresherIDParentSecond + `":"ok"}}`,
		wantRefreshers: []string{testRefresherIDParentFirst, testRefresherIDParentSecond},
	}, {
		name:    "success_all_refreshers",
		reqBody: `{"ids":["*"]}`,
		wantResp: `{"results":{"` + testRefresherIDParentFirst + `":"ok","` +
			testRefresherIDParentSecond + `":"ok","` + testRefresherID + `":"ok"}}`,
		wantRefreshers: []string{
			testRefresherIDParentFirst,
			testRefresherIDParentSecond,
			testRefresherID,
		},
	}}

	for _, tc := range testCases {
		signalCh := make(chan string, len(tc.wantRefreshers))

		refreshers := debugsvc.Refreshers{
			testRefresherID:             newTestRefresher(t, testRefresherID, signalCh),
			testRefresherIDParentFirst:  newTestRefresher(t, testRefresherIDParentFirst, signalCh),
			testRefresherIDParentSecond: newTestRefresher(t, testRefresherIDParentSecond, signalCh),
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &debugsvc.Config{
				APIAddr:    localhostAnyPort,
				Refreshers: refreshers,
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

			refreshURL := srvURL.JoinPath(debugsvc.PathPatternDebugAPIRefresh)

			reqBody := strings.NewReader(tc.reqBody)

			resp, err := client.Post(refreshURL.String(), agdhttp.HdrValApplicationJSON, reqBody)
			require.NoError(t, err)

			gotRefreshers := []string{}
			for range tc.wantRefreshers {
				refresherName, ok := testutil.RequireReceive(t, signalCh, testTimeout)
				require.True(t, ok)

				gotRefreshers = append(gotRefreshers, refresherName)
			}

			assert.ElementsMatch(t, tc.wantRefreshers, gotRefreshers)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			respBody := readRespBody(t, resp)
			assert.JSONEq(t, tc.wantResp, respBody)
		})
	}
}

// newTestRefresher creates a new instance of [*fakeservice.Refresher].  ch must
// not be nil.
func newTestRefresher(
	tb testing.TB,
	refresherName string,
	ch chan<- string,
) (r *fakeservice.Refresher) {
	tb.Helper()

	return &fakeservice.Refresher{
		OnRefresh: func(_ context.Context) (err error) {
			pt := testutil.NewPanicT(tb)

			testutil.RequireSend(pt, ch, refresherName, testTimeout)

			return nil
		},
	}
}

func TestService_Start_refreshAPIErrors(t *testing.T) {
	t.Parallel()

	c := &debugsvc.Config{
		APIAddr: localhostAnyPort,
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

	refreshURL := srvURL.JoinPath(debugsvc.PathPatternDebugAPIRefresh)

	refreshURLStr := refreshURL.String()

	testCases := []struct {
		name     string
		reqBody  string
		wantResp string
	}{{
		name:     "error_invalid_id",
		reqBody:  `{"ids":["test","*"]}`,
		wantResp: `"*" cannot be used with other ids` + "\n",
	}, {
		name:     "error_no_ids",
		reqBody:  `{}`,
		wantResp: `no ids` + "\n",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reqBody := strings.NewReader(tc.reqBody)
			resp, err := client.Post(refreshURLStr, agdhttp.HdrValApplicationJSON, reqBody)
			require.NoError(t, err)

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

			respBody := readRespBody(t, resp)
			assert.Equal(t, tc.wantResp, respBody)
		})
	}
}
