package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testMaxAge is a test maximum age of files in the filter cache.
	testMaxAge = 1 * time.Second

	// testFileName is a test name for a cache file.
	testFileName = "test"

	// testTimeout is a test timeout for tests.
	testTimeout = time.Second * 1
)

var (
	// fakeClock is a fake [*faketime.Clock] for tests.
	fakeClock = &faketime.Clock{
		OnNow: func() (t time.Time) {
			now := time.Now().Add(testMaxAge)

			return now
		},
	}

	// testLogger is a discard logger for tests.
	testLogger = slogutil.NewDiscardLogger()
)

func TestWalker_walk(t *testing.T) {
	t.Parallel()

	fs := fstest.MapFS{
		testFileName: &fstest.MapFile{},
		filepath.Join(filter.SubDirNameRuleList, testFileName): &fstest.MapFile{},
	}

	testCases := []struct {
		clock       timeutil.Clock
		name        string
		wantRemoved []string
	}{{
		name:        "success_no_files_to_remove",
		wantRemoved: []string(nil),
		clock:       timeutil.SystemClock{},
	}, {
		name:        "success_cleaned",
		wantRemoved: []string{testFileName},
		clock:       fakeClock,
	}, {
		name:        "success_cleaned_rulelist_subdir",
		wantRemoved: []string{filepath.Join(filter.SubDirNameRuleList, testFileName)},
		clock:       fakeClock,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cacheDir := t.TempDir()

			err := os.CopyFS(cacheDir, fs)
			require.NoError(t, err)

			cw := newWalker(&walkerConfig{
				errColl:  agdtest.NewErrorCollector(),
				logger:   testLogger,
				clock:    tc.clock,
				cacheDir: cacheDir,
				maxAge:   timeutil.Duration(testMaxAge),
			})

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			cw.walk(ctx)
			require.NoError(t, err)

			for _, wantRmFile := range tc.wantRemoved {
				assert.NoFileExists(t, filepath.Join(cacheDir, wantRmFile))
			}
		})
	}
}

func TestWalker_walkError(t *testing.T) {
	t.Parallel()

	const (
		dirName    = "/no/dir"
		wantErrMsg = `walking dir: lstat ` + dirName + `: no such file or directory`
	)

	fakeErrColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			pt := testutil.NewPanicT(t)
			testutil.AssertErrorMsg(pt, wantErrMsg, err)
		},
	}

	cw := newWalker(&walkerConfig{
		errColl:  fakeErrColl,
		logger:   testLogger,
		clock:    &timeutil.SystemClock{},
		cacheDir: dirName,
		maxAge:   timeutil.Duration(testMaxAge),
	})

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	cw.walk(ctx)
}
