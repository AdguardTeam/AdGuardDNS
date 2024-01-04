package errcoll

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/AdguardTeam/golibs/errors"
)

// WriterErrorCollector is an [Interface] implementation that writes errors to
// an [io.Writer].
type WriterErrorCollector struct {
	w io.Writer
}

// NewWriterErrorCollector returns a new properly initialized
// *WriterErrorCollector.
func NewWriterErrorCollector(w io.Writer) (c *WriterErrorCollector) {
	return &WriterErrorCollector{
		w: w,
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
		time.Now(),
		err,
		isIface,
		isReportable,
	)
}
