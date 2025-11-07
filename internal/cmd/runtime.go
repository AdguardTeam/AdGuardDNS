package cmd

import (
	"context"
	"log/slog"
	"runtime/debug"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// setMaxThreads sets the maximum number of threads for the Go runtime, if
// necessary.  l must not be nil, n must not be negative.
func setMaxThreads(ctx context.Context, l *slog.Logger, n int) {
	if n == 0 {
		l.Log(ctx, slogutil.LevelTrace, "go max threads not set")

		return
	}

	debug.SetMaxThreads(n)

	l.InfoContext(ctx, "set go max threads", "n", n)
}
