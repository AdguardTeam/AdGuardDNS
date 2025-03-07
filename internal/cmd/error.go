package cmd

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// reportPanics reports all panics in Main using the Sentry client, logs them,
// and repanics.  It should be called in a defer.
//
// TODO(a.garipov):  Consider switching to pure Sentry.
func reportPanics(ctx context.Context, errColl errcoll.Interface, l *slog.Logger) {
	v := recover()
	if v == nil {
		return
	}

	err := errors.FromRecovered(v)
	l.ErrorContext(ctx, "recovered from panic", slogutil.KeyError, err)
	slogutil.PrintStack(ctx, l, slog.LevelError)

	errColl.Collect(ctx, err)
	errFlushColl, ok := errColl.(errcoll.ErrorFlushCollector)
	if ok {
		errFlushColl.Flush()
	}

	panic(v)
}
