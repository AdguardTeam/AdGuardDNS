package internal_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refrID is the ID of a [agd.FilterList] used for testing.
const refrID = "test_id"

func TestRefreshable_Refresh(t *testing.T) {
	const (
		defaultFileText = "||filefilter.example\n"
		defaultURLText  = "||urlfilter.example\n"
	)

	testCases := []struct {
		name         string
		wantText     string
		wantErrMsg   string
		srvText      string
		staleness    time.Duration
		srvCode      int
		acceptStale  bool
		expectReq    bool
		useCacheFile bool
	}{{
		name:         "no_file",
		wantText:     defaultURLText,
		wantErrMsg:   "",
		srvText:      defaultURLText,
		staleness:    0,
		srvCode:      http.StatusOK,
		acceptStale:  true,
		expectReq:    true,
		useCacheFile: false,
	}, {
		name:     "no_file_http_empty",
		wantText: "",
		wantErrMsg: refrID + `: refreshing from url "URL": ` +
			`server "` + filtertest.ServerName + `": empty text, not resetting`,
		srvText:      "",
		staleness:    0,
		srvCode:      http.StatusOK,
		acceptStale:  true,
		expectReq:    true,
		useCacheFile: false,
	}, {
		name:     "no_file_http_error",
		wantText: "",
		wantErrMsg: refrID + `: refreshing from url "URL": ` +
			`server "` + filtertest.ServerName + `": ` +
			`status code error: expected 200, got 500`,
		srvText:      "internal server error",
		staleness:    0,
		srvCode:      http.StatusInternalServerError,
		acceptStale:  true,
		expectReq:    true,
		useCacheFile: false,
	}, {
		name:         "file",
		wantText:     defaultFileText,
		wantErrMsg:   "",
		srvText:      "",
		staleness:    1 * time.Hour,
		srvCode:      0,
		acceptStale:  true,
		expectReq:    false,
		useCacheFile: true,
	}, {
		name:         "file_stale",
		wantText:     defaultURLText,
		wantErrMsg:   "",
		srvText:      defaultURLText,
		staleness:    -1 * time.Hour,
		srvCode:      http.StatusOK,
		acceptStale:  false,
		expectReq:    true,
		useCacheFile: true,
	}, {
		name:         "file_stale_accept",
		wantText:     defaultFileText,
		wantErrMsg:   "",
		srvText:      "",
		staleness:    -1 * time.Hour,
		srvCode:      0,
		acceptStale:  true,
		expectReq:    false,
		useCacheFile: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			reqCh := make(chan struct{}, 1)
			var cachePath string
			realCachePath, srvURL := filtertest.PrepareRefreshable(t, reqCh, tc.srvText, tc.srvCode)
			if tc.useCacheFile {
				cachePath = realCachePath

				err = os.WriteFile(cachePath, []byte(defaultFileText), 0o600)
				require.NoError(t, err)
			} else {
				cachePath = filepath.Join(t.TempDir(), "does_not_exist")
			}

			fl := &agd.FilterList{
				URL:        srvURL,
				ID:         refrID,
				RefreshIvl: tc.staleness,
			}
			f := internal.NewRefreshable(fl, cachePath)

			ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
			t.Cleanup(cancel)

			var gotText string
			gotText, err = f.Refresh(ctx, tc.acceptStale)
			if tc.expectReq {
				testutil.RequireReceive(t, reqCh, filtertest.Timeout)
			}

			// Since we only get the actual URL within the subtest, replace it
			// here and check the error message.
			if srvURL != nil {
				tc.wantErrMsg = strings.ReplaceAll(tc.wantErrMsg, "URL", srvURL.String())
			}

			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantText, gotText)
		})
	}
}

func TestRefreshable_Refresh_properStaleness(t *testing.T) {
	const (
		responseDur = time.Second / 5
		staleness   = time.Hour
	)

	reqCh := make(chan struct{})
	cachePath, addr := filtertest.PrepareRefreshable(t, reqCh, filtertest.BlockRule, http.StatusOK)

	fl := &agd.FilterList{
		URL:        addr,
		ID:         refrID,
		RefreshIvl: staleness,
	}
	f := internal.NewRefreshable(fl, cachePath)

	ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
	t.Cleanup(cancel)

	var err error
	var now time.Time
	go func() {
		<-reqCh
		now = time.Now()
		_, err = f.Refresh(ctx, false)
		<-reqCh
	}()

	// Start the refresh.
	reqCh <- struct{}{}

	// Hold the handler to guarantee the refresh will endure some time.
	time.Sleep(responseDur)

	// Continue the refresh.
	testutil.RequireReceive(t, reqCh, filtertest.Timeout)

	// Ensure the refresh finished.
	reqCh <- struct{}{}

	require.NoError(t, err)

	file, err := os.Open(cachePath)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, file.Close)

	fi, err := file.Stat()
	require.NoError(t, err)

	assert.InDelta(t, fi.ModTime().Sub(now), 0, float64(time.Millisecond))
}
