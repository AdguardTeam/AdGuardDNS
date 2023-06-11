package agdhttp_test

import (
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestCheckStatus(t *testing.T) {
	testCases := []struct {
		name       string
		srv        string
		wantErrMsg string
		exp        int
		got        int
	}{{
		name:       "200_200",
		srv:        testSrv,
		wantErrMsg: "",
		exp:        200,
		got:        200,
	}, {
		name:       "200_404",
		srv:        "",
		wantErrMsg: `server "": status code error: expected 200, got 404`,
		exp:        200,
		got:        404,
	}, {
		name:       "200_404_srv",
		srv:        testSrv,
		wantErrMsg: `server "` + testSrv + `": status code error: expected 200, got 404`,
		exp:        200,
		got:        404,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.got,
				Header: http.Header{
					httphdr.Server: []string{tc.srv},
				},
			}
			err := agdhttp.CheckStatus(resp, tc.exp)

			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestServerError(t *testing.T) {
	testCases := []struct {
		err        error
		name       string
		srv        string
		wantErrMsg string
	}{{
		err:        testError,
		name:       "no_srv",
		srv:        "",
		wantErrMsg: `server "": ` + string(testError),
	}, {
		err:        testError,
		name:       "with_srv",
		srv:        testSrv,
		wantErrMsg: `server "` + testSrv + `": ` + string(testError),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{
					httphdr.Server: []string{tc.srv},
				},
			}
			err := agdhttp.WrapServerError(tc.err, resp)

			assert.ErrorIs(t, err, tc.err)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
