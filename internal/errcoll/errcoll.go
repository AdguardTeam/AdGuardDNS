// Package errcoll contains implementations of error collectors, most notably
// Sentry.
package errcoll

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// Interface is the interface for error collectors that process information
// about errors, possibly sending them to a remote location.
type Interface interface {
	Collect(ctx context.Context, err error)
}

// Collectf is a helper method for reporting non-critical errors.  It writes the
// resulting error into the log and also into errColl.
func Collectf(ctx context.Context, errColl Interface, format string, args ...any) {
	err := fmt.Errorf(format, args...)
	log.Error("%s", err)
	errColl.Collect(ctx, err)
}

// Collect is a helper method for reporting non-critical errors.  It writes the
// resulting error into the log and also into errColl.
//
// TODO(a.garipov):  Find a way to extract the prefix from l and add to err.
func Collect(ctx context.Context, errColl Interface, l *slog.Logger, msg string, err error) {
	l.ErrorContext(ctx, msg, slogutil.KeyError, err)
	errColl.Collect(ctx, fmt.Errorf("%s: %w", msg, err))
}
