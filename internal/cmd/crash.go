package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/service"
)

// crashReporter is a helper that sets a file for Go runtime crashes and
// unhandled panics.
type crashReporter struct {
	file   *os.File
	logger *slog.Logger

	dirPath string
	pattern string
}

// crashReporterConfig is the configuration structure for a [crashReporter].
type crashReporterConfig struct {
	// logger is used to log the operation of the crash reporter.  If enabled is
	// true, logger must not be nil.
	logger *slog.Logger

	// dirPath is the path to the directory where the crash report is created.
	// If enabled is true, dirPath should not be nil and should point to a
	// directory.
	dirPath string

	// prefix is the prefix to use when creating the file.  If enabled is true,
	// prefix should not be nil.
	prefix string

	// enabled shows if a crash report file should be created.
	enabled bool
}

// newCrashReporter returns a new properly initialized crash reporter.  c must
// not be nil and must be valid.
//
// TODO(a.garipov):  Consider moving to golibs.
func newCrashReporter(c *crashReporterConfig) (r *crashReporter, err error) {
	defer func() { err = errors.Annotate(err, "crash reporter: %w") }()

	if !c.enabled {
		return nil, nil
	}

	err = validateDir(c.dirPath)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is, and
		// there is already errors.Annotate here.
		return nil, err
	}

	pat := fmt.Sprintf(
		"%s_%s_%07d_*.txt",
		c.prefix,
		time.Now().Format("20060102150405"),
		os.Getpid(),
	)

	return &crashReporter{
		logger:  c.logger,
		dirPath: c.dirPath,
		pattern: pat,
	}, nil
}

// type check
var _ service.Interface = (*crashReporter)(nil)

// Start implements the [service.Interface] for *crashReporter.  If r is nil,
// err is nil.
func (r *crashReporter) Start(ctx context.Context) (err error) {
	if r == nil {
		return nil
	}

	defer func() { err = errors.Annotate(err, "starting crash reporter: %w") }()

	r.logger.InfoContext(ctx, "creating crash output file")

	r.file, err = os.CreateTemp(r.dirPath, r.pattern)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is, and
		// there is already errors.Annotate here.
		return err
	}

	r.logger = r.logger.With("path", r.file.Name())

	r.logger.InfoContext(ctx, "setting crash output")

	err = debug.SetCrashOutput(r.file, debug.CrashOptions{})
	if err != nil {
		return fmt.Errorf("setting crash output: %w", err)
	}

	r.logger.DebugContext(ctx, "set crash output")

	return nil
}

// Shutdown implements the [service.Interface] for *crashReporter.  If r is nil,
// err is nil.
func (r *crashReporter) Shutdown(ctx context.Context) (err error) {
	if r == nil {
		return nil
	}

	r.logger.InfoContext(ctx, "closing crash output")

	s, err := r.file.Stat()
	if err != nil {
		return fmt.Errorf("getting stat of crash file: %w", err)
	}

	if s.Size() > 0 {
		r.logger.InfoContext(ctx, "crash output is not empty; not removing")

		return nil
	}

	name := r.file.Name()
	err = r.file.Close()
	if err != nil {
		return fmt.Errorf("closing crash file: %w", err)
	}

	r.logger.InfoContext(ctx, "crash output is empty; removing")

	err = os.Remove(name)
	if err != nil {
		return fmt.Errorf("removing crash file: %w", err)
	}

	return nil
}
