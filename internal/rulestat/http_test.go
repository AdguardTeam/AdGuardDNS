package rulestat_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handleWithURL starts the test server with h, finishes it on cleanup, and
// returns it's URL.
func handleWithURL(t *testing.T, h http.Handler) (u *url.URL) {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	return u
}

func TestHTTP_Collect(t *testing.T) {
	b := &bytes.Buffer{}
	u := handleWithURL(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		pt := testutil.PanicT{}

		_, err := io.Copy(b, r.Body)
		require.NoError(pt, err)

		rw.WriteHeader(http.StatusOK)
	}))
	conf := &rulestat.HTTPConfig{
		Logger:  slogutil.NewDiscardLogger(),
		ErrColl: agdtest.NewErrorCollector(),
		Metrics: rulestat.EmptyMetrics{},
		URL:     u,
	}

	testCases := []struct {
		name  string
		want  string
		rules []filter.RuleText
	}{{
		name:  "single",
		want:  `{"filters":{"15":{"||example.org^":1}}}`,
		rules: []filter.RuleText{"||example.org^"},
	}, {
		name:  "several_alike",
		want:  `{"filters":{"15":{"||example.org^":3}}}`,
		rules: []filter.RuleText{"||example.org^", "||example.org^", "||example.org^"},
	}, {
		name:  "several_different",
		want:  `{"filters":{"15":{"||example.org^":1, "||example.com^":1, "||пример.рф^":1}}}`,
		rules: []filter.RuleText{"||example.org^", "||example.com^", "||пример.рф^"},
	}}

	for _, tc := range testCases {
		b.Reset()
		h := rulestat.NewHTTP(conf)

		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			for _, rule := range tc.rules {
				h.Collect(ctx, filter.IDAdGuardDNS, rule)
			}

			// Use the context different from the above one.
			err := h.Refresh(testutil.ContextWithTimeout(t, testTimeout))
			require.NoError(t, err)

			assert.JSONEq(t, tc.want, b.String())
		})
	}
}

func TestHTTP_Refresh_errors(t *testing.T) {
	t.Run("bad_url", func(t *testing.T) {
		const wantErrMsg = `uploading filter stats: Post "badscheme://0.0.0.0": ` +
			`unsupported protocol scheme "badscheme"`

		h := rulestat.NewHTTP(&rulestat.HTTPConfig{
			Logger: slogutil.NewDiscardLogger(),
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, err error) {
					testutil.AssertErrorMsg(t, "uploading rulestat: "+wantErrMsg, err)
				},
			},
			Metrics: rulestat.EmptyMetrics{},
			URL: &url.URL{
				Scheme: "badscheme",
				Host:   "0.0.0.0",
			},
		})

		err := h.Refresh(testutil.ContextWithTimeout(t, testTimeout))
		testutil.AssertErrorMsg(t, wantErrMsg, err)
	})

	t.Run("bad_response", func(t *testing.T) {
		u := handleWithURL(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
		}))
		h := rulestat.NewHTTP(&rulestat.HTTPConfig{
			Logger: slogutil.NewDiscardLogger(),
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, err error) {
					require.NotNil(t, err)
				},
			},
			Metrics: rulestat.EmptyMetrics{},
			URL:     u,
		})

		var serr *agdhttp.StatusError
		err := h.Refresh(testutil.ContextWithTimeout(t, testTimeout))
		require.ErrorAs(t, err, &serr)

		assert.Equal(t, http.StatusInternalServerError, serr.Got)
	})
}
