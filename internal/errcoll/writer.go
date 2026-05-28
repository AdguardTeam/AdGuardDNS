package errcoll

import (
	"context"
	"fmt"
	"io"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// WriterErrorCollector is an [Interface] implementation that writes errors to
// an [io.Writer].
type WriterErrorCollector struct {
	clock timeutil.Clock
	w     io.Writer
}

// WriterErrorCollectorConfig is the configuration for [WriterErrorCollector].
type WriterErrorCollectorConfig struct {
	// Clock is used to get the current time.  It must not be nil.
	Clock timeutil.Clock

	// Writer is the writer to write errors to.  It must not be nil.
	Writer io.Writer
}

// NewWriterErrorCollector returns a new properly initialized
// *WriterErrorCollector.  c must be valid.
func NewWriterErrorCollector(c *WriterErrorCollectorConfig) (coll *WriterErrorCollector) {
	return &WriterErrorCollector{
		clock: c.Clock,
		w:     c.Writer,
	}
}

// type check
var _ Interface = (*WriterErrorCollector)(nil)

// Collect implements the [Interface] interface for *WriterErrorCollector.
func (c *WriterErrorCollector) Collect(ctx context.Context, err error) {
	var (
		sentryRepErr SentryReportableError
		isIface      bool
		isReportable bool
	)
	if isIface = errors.As(err, &sentryRepErr); isIface {
		isReportable = sentryRepErr.IsSentryReportable()
	}

	_, _ = fmt.Fprintf(
		c.w,
		"%s: caught error: %s (sentry iface: %t, reportable: %t)\n",
		c.clock.Now(),
		err,
		isIface,
		isReportable,
	)
}
