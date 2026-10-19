package tlsconfig_test

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaleFileGC_Clean(t *testing.T) {
	t.Parallel()

	const (
		// maxAge is a maximum age of files in the target directory.
		maxAge = 1 * time.Second

		// subDirName is a test subdirectory name in the target directory.
		subDirName = "sub"

		// excludedFileName is a name for a file to be excluded from garbage
		// collection.
		excludedFileName = "excluded"

		// staleFileName is a name for a stale test file.
		staleFileName = "stale"
	)

	fakeClock := &faketime.Clock{
		OnNow: func() (t time.Time) {
			return time.Now().Add(maxAge)
		},
	}

	subDirStaleFileName := filepath.Join(subDirName, staleFileName)

	fs := fstest.MapFS{
		staleFileName:       &fstest.MapFile{},
		subDirStaleFileName: &fstest.MapFile{},
		excludedFileName:    &fstest.MapFile{},
	}

	testCases := []struct {
		clock         timeutil.Clock
		name          string
		exclusions    *container.SortedSliceSet[string]
		wantPreserved []string
		wantRemoved   []string
	}{{
		clock:         timeutil.SystemClock{},
		name:          "success_no_files_to_remove",
		exclusions:    container.NewSortedSliceSet[string](),
		wantPreserved: []string{staleFileName, excludedFileName, subDirStaleFileName},
		wantRemoved:   []string(nil),
	}, {
		clock:         fakeClock,
		name:          "success",
		exclusions:    container.NewSortedSliceSet[string](),
		wantPreserved: []string{subDirStaleFileName},
		wantRemoved:   []string{staleFileName, excludedFileName},
	}, {
		clock:         fakeClock,
		name:          "success_with_exclusions",
		exclusions:    container.NewSortedSliceSet(excludedFileName),
		wantPreserved: []string{excludedFileName, subDirStaleFileName},
		wantRemoved:   []string{staleFileName},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			targetDir := t.TempDir()

			err := os.CopyFS(targetDir, fs)
			require.NoError(t, err)

			gc := tlsconfig.NewStaleFileGC(&tlsconfig.StaleFileGCConfig{
				Clock:      tc.clock,
				Logger:     testLogger,
				ErrColl:    testErrColl,
				TargetDir:  targetDir,
				Exclusions: tc.exclusions,
				MaxAge:     maxAge,
			})

			gc.Clean(testutil.ContextWithTimeout(t, testTimeout))

			for _, wantRmFile := range tc.wantRemoved {
				assert.NoFileExists(t, filepath.Join(targetDir, wantRmFile))
			}

			for _, wantPreservedFile := range tc.wantPreserved {
				assert.FileExists(t, filepath.Join(targetDir, wantPreservedFile))
			}
		})
	}
}
