package agdhttp_test

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestParseHTTPURL(t *testing.T) {
	goodURL := testURL()

	badSchemeURL := netutil.CloneURL(goodURL)
	badSchemeURL.Scheme = "ftp"

	relativeURL := &url.URL{
		Path: "/a/b/c/",
	}

	testCases := []struct {
		want       *url.URL
		name       string
		in         string
		wantErrMsg string
	}{{
		want:       goodURL,
		name:       "ok",
		in:         goodURL.String(),
		wantErrMsg: ``,
	}, {
		want:       nil,
		name:       "invalid",
		in:         "\n",
		wantErrMsg: `parse "\n": net/url: invalid control character in URL`,
	}, {
		want:       nil,
		name:       "bad_scheme",
		in:         badSchemeURL.String(),
		wantErrMsg: `parse "` + badSchemeURL.String() + `": bad scheme "ftp"`,
	}, {
		want:       nil,
		name:       "relative",
		in:         relativeURL.Path,
		wantErrMsg: `parse "/a/b/c/": empty host`,
	}, {
		want:       nil,
		name:       "empty",
		in:         "",
		wantErrMsg: `parse "": empty host`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := agdhttp.ParseHTTPURL(tc.in)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func testURL() (u *url.URL) {
	return &url.URL{
		Scheme:   "http",
		User:     url.UserPassword("user", "pass"),
		Host:     "example.com",
		Path:     "/a/b/c/",
		RawQuery: "d=e",
		Fragment: "f",
	}
}
