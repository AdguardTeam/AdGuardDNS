package dnsserver

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/panjf2000/ants/v2"
)

// antsLogger implements the [ants.Logger] interface and writes everything
// to its logger.
type antsLogger struct {
	logger *slog.Logger
}

// type check
var _ ants.Logger = (*antsLogger)(nil)

// Printf implements the [ants.Logger] interface for *antsLogger.
func (l *antsLogger) Printf(format string, args ...interface{}) {
	l.logger.Info("ants pool", slogutil.KeyMessage, fmt.Sprintf(format, args...))
}

// mustNewPoolNonblocking creates a new instance of [*ants.Pool] configured
// optimally for using it in DNS servers.  It panics if there are errors.
// logger must not be nil.
func mustNewPoolNonblocking(logger *slog.Logger) (p *ants.Pool) {
	p, err := ants.NewPool(0, ants.WithOptions(ants.Options{
		ExpiryDuration: time.Minute,
		PreAlloc:       false,
		Nonblocking:    true,
		DisablePurge:   false,
		Logger: &antsLogger{
			logger: logger,
		},
	}))
	errors.Check(err)

	return p
}
