package agd

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/log"
)

// Error Collector

// ErrorCollector collects information about errors, possibly sending them to
// a remote location.
type ErrorCollector interface {
	Collect(ctx context.Context, err error)
}

// Collectf is a helper method for reporting non-critical errors.  It writes the
// resulting error into the log and also into the error collector.
func Collectf(ctx context.Context, errColl ErrorCollector, format string, args ...any) {
	err := fmt.Errorf(format, args...)
	log.Error("%s", err)
	errColl.Collect(ctx, err)
}
