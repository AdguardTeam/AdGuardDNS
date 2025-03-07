// Package errcoll contains implementations of error collectors, most notably
// Sentry.
package errcoll

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
)

// Interface is the interface for error collectors that process information
// about errors, possibly sending them to a remote location.
type Interface interface {
	Collect(ctx context.Context, err error)
}

// Collect is a helper method for reporting non-critical errors.  It writes the
// resulting error into the log and also into errColl.
//
// TODO(a.garipov):  Find a way to extract the prefix from l and add to err.
func Collect(ctx context.Context, errColl Interface, l *slog.Logger, msg string, err error) {
	l.ErrorContext(ctx, msg, slogutil.KeyError, err)
	errColl.Collect(ctx, fmt.Errorf("%s: %w", msg, err))
}

// RefreshErrorHandler is a [service.ErrorHandler] that can be used whenever a
// [service.Refresher] cannot report its own errors for some reason.
type RefreshErrorHandler struct {
	logger  *slog.Logger
	errColl Interface
}

// NewRefreshErrorHandler returns a properly initialized *RefreshErrorHandler.
// All arguments must not be nil.
func NewRefreshErrorHandler(logger *slog.Logger, errColl Interface) (h *RefreshErrorHandler) {
	return &RefreshErrorHandler{
		logger:  logger,
		errColl: errColl,
	}
}

// type check
var _ service.ErrorHandler = (*RefreshErrorHandler)(nil)

// Handle implements the [service.ErrorHandler] interface for
// *RefreshErrorHandler.
func (h *RefreshErrorHandler) Handle(ctx context.Context, err error) {
	Collect(ctx, h.errColl, h.logger, "refreshing", err)
}
