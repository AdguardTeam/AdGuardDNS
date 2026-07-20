package agdruntime

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/golibs/service"
)

// RefresherConfig is the configuration for the refresher.  See [NewRefresher].
// All fields must not be empty.
type RefresherConfig struct {
	// Logger is used for logging internal operations.
	Logger *slog.Logger

	// Manager is used to manage OS threads.
	Manager Manager

	// Limit is the limit of OS threads.
	Limit uint
}

// Refresher implements the [service.Refresher] interface that refreshes the
// runtime by terminating the OS threads.
//
// TODO(d.kolyshev):  Use.
type Refresher struct {
	logger  *slog.Logger
	manager Manager
	limit   uint
}

// NewRefresher returns a properly initialized *Refresher.  c must not be nil.
func NewRefresher(c *RefresherConfig) (r *Refresher) {
	return &Refresher{
		logger:  c.Logger,
		manager: c.Manager,
		limit:   c.Limit,
	}
}

// type check
var _ service.Refresher = (*Refresher)(nil)

// Refresh implements the [service.Refresher] interface for *Refresher.
func (r *Refresher) Refresh(ctx context.Context) (err error) {
	r.logger.InfoContext(ctx, "refresh started")
	defer r.logger.InfoContext(ctx, "refresh finished")

	c := r.manager.ThreadsCount()
	r.logger.DebugContext(ctx, "current os thread count", "number", c)

	if c > r.limit {
		delta := c - r.limit

		r.logger.InfoContext(ctx, "terminating os threads", "count", delta)

		r.killOSThreads(delta)
	}

	return nil
}

// killOSThreads terminates a count of OS threads.
func (r *Refresher) killOSThreads(count uint) {
	for range count {
		done := make(chan struct{})
		go func() {
			defer close(done)

			r.manager.TerminateThread()
		}()

		<-done
	}
}
