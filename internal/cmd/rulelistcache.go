package cmd

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// walker walks through cache and clean it.
type walker struct {
	// clock is used to retrieve the current time.
	clock timeutil.Clock

	// errColl is used to collect errors during walks through the cache.
	errColl errcoll.Interface

	// logger is used to log operations of [walker].
	logger *slog.Logger

	// cacheDir is a path to the cache directory.
	cacheDir string

	// maxAge is a max age of files in the cache.
	maxAge time.Duration
}

// walkerConfig is a configuration structure for the [*walker].
type walkerConfig struct {
	// clock is used to retrieve the current time.  It must not be nil.
	clock timeutil.Clock

	// errColl is used to collect errors during walks through cache.  It must
	// not be nil.
	errColl errcoll.Interface

	// logger is used to log operations of [walker].  It must not be nil.
	logger *slog.Logger

	// cacheDir is a path to the cache directory.  It must not be an empty
	// string.
	cacheDir string

	// maxAge is a max age of files in the cache.
	maxAge timeutil.Duration
}

// newWalker creates a new instance of [*walker].  c must be valid and must not
// be nil.
func newWalker(c *walkerConfig) (w *walker) {
	return &walker{
		errColl:  c.errColl,
		logger:   c.logger.With(slogutil.KeyPrefix, "walker"),
		clock:    c.clock,
		cacheDir: c.cacheDir,
		maxAge:   time.Duration(c.maxAge),
	}
}

// walk walks through a directory and cleans stale files from it.
func (w *walker) walk(ctx context.Context) {
	w.logger.InfoContext(ctx, "walking through filter cache", "cache_dir", w.cacheDir)

	err := filepath.WalkDir(w.cacheDir, func(path string, d fs.DirEntry, walkErr error) (err error) {
		if walkErr != nil {
			return fmt.Errorf("walking dir: %w", walkErr)
		}

		isTarget, err := isTargetForCleaning(path, w.cacheDir, d)
		if err != nil {
			return err
		}
		if !isTarget {
			return nil
		}

		err = w.removeIfStale(ctx, d, path)
		if err != nil {
			// Don't wrap the error as it is informative as is.
			return err
		}

		return nil
	})
	if err != nil {
		w.logger.ErrorContext(ctx, "failed to walk through filter cache", slogutil.KeyError, err)
		w.errColl.Collect(ctx, err)
	}
}

// isTargetForCleaning checks whether an object in the path is a target for
// cleaning.
func isTargetForCleaning(path, cacheDir string, d fs.DirEntry) (ok bool, err error) {
	if d.IsDir() {
		if path == cacheDir || filepath.Base(path) == filter.SubDirNameRuleList {
			return false, nil
		}

		return false, filepath.SkipDir
	}

	return true, nil
}

// removeIfStale checks whether the file is stale and, if so, deletes it.  path
// must not be an empty string.
func (w *walker) removeIfStale(ctx context.Context, d fs.DirEntry, path string) (err error) {
	fInfo, err := d.Info()
	if err != nil {
		return fmt.Errorf("getting file info: %w", err)
	}

	mtime := fInfo.ModTime()

	if w.clock.Now().Sub(mtime) < w.maxAge {
		return nil
	}

	w.logger.InfoContext(
		ctx,
		"removing stale file from filter cache",
		"path", path,
		"mod_time", mtime.String(),
	)
	err = os.Remove(path)
	if err != nil {
		return fmt.Errorf("removing file from cache: %w", err)
	}

	return nil
}
