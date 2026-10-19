package tlsconfig

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/timeutil"
)

// StaleFileGCConfig is the configuration for the stale files garbage collector.
type StaleFileGCConfig struct {
	// Clock is used to retrieve the current time.  It must not be nil.
	Clock timeutil.Clock

	// ErrColl is used to collect errors.  It must not be nil.
	ErrColl errcoll.Interface

	// Exclusions is a list of file names to exclude from garbage collection.
	Exclusions *container.SortedSliceSet[string]

	// Logger is used to log operations of [StaleFileGC].  It must not be nil.
	Logger *slog.Logger

	// TargetDir is a path to the target directory.
	//
	// TODO(d.kolyshev):  Use [os.Root].
	TargetDir string

	// MaxAge is a max age of files in the target directory.  It must be
	// positive.
	MaxAge time.Duration
}

// StaleFileGC is a garbage collector for stale files.
//
// TODO(a.garipov):  Consider moving to golibs.
type StaleFileGC struct {
	clock      timeutil.Clock
	errColl    errcoll.Interface
	exclusions *container.SortedSliceSet[string]
	logger     *slog.Logger
	targetDir  string
	maxAge     time.Duration
}

// NewStaleFileGC returns a properly initialized *StaleFileGC.  c must be valid.
func NewStaleFileGC(c *StaleFileGCConfig) (gc *StaleFileGC) {
	return &StaleFileGC{
		clock:      c.Clock,
		errColl:    c.ErrColl,
		logger:     c.Logger.With("target_dir", c.TargetDir),
		targetDir:  c.TargetDir,
		exclusions: c.Exclusions,
		maxAge:     c.MaxAge,
	}
}

// Clean walks through the target directory and cleans stale files from it.
func (gc *StaleFileGC) Clean(ctx context.Context) {
	gc.logger.InfoContext(ctx, "cleaning")
	defer gc.logger.InfoContext(ctx, "finished")

	entries, err := os.ReadDir(gc.targetDir)
	if err != nil {
		errcoll.Collect(ctx, gc.errColl, gc.logger, "reading target dir", err)

		return
	}

	now := gc.clock.Now()

	for _, ent := range entries {
		if ent.IsDir() {
			// Skip subdirectories.
			continue
		}

		entName := ent.Name()
		if gc.exclusions.Has(entName) {
			gc.logger.DebugContext(ctx, "skipping excluded file", "file", entName)

			continue
		}

		err = gc.removeIfStale(ctx, ent, now)
		if err != nil {
			errcoll.Collect(ctx, gc.errColl, gc.logger, "removing stale file", err)
		}
	}
}

// removeIfStale checks whether the file is stale and, if so, deletes it.  ent
// must not be nil.
func (gc *StaleFileGC) removeIfStale(
	ctx context.Context,
	ent fs.DirEntry,
	now time.Time,
) (err error) {
	fi, err := ent.Info()
	if err != nil {
		return fmt.Errorf("getting file info: %w", err)
	}

	mtime := fi.ModTime()

	if now.Sub(mtime) < gc.maxAge {
		return nil
	}

	path := filepath.Join(gc.targetDir, ent.Name())

	gc.logger.InfoContext(ctx, "removing stale file", "path", path, "mod_time", mtime.String())

	err = os.Remove(path)
	if err != nil {
		return fmt.Errorf("removing file: %w", err)
	}

	return nil
}
