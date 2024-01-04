// Package errcoll contains implementations of error collectors, most notably
// Sentry.
package errcoll

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/log"
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
