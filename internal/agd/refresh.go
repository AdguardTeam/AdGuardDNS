package agd

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/log"
)

// Refreshable Entities And Utilities

// Refresher is the interface for entities that can update themselves.
type Refresher interface {
	Refresh(ctx context.Context) (err error)
}

var _ Service = (*RefreshWorker)(nil)

// RefreshWorker is a Service that updates its refreshable entity every tick of
// the provided ticker.
type RefreshWorker struct {
	done       chan unit
	context    func() (ctx context.Context, cancel context.CancelFunc)
	logRoutine func(format string, args ...any)
	tick       *time.Ticker
	refr       Refresher
	errColl    ErrorCollector
	name       string

	refrOnShutdown bool
}

// RefreshWorkerConfig is the configuration structure for a *RefreshWorker.
type RefreshWorkerConfig struct {
	// Context is used to provide a context for the Refresh method of Refresher.
	Context func() (ctx context.Context, cancel context.CancelFunc)

	// Refresher is the entity being refreshed.
	Refresher Refresher

	// ErrColl is used to collect errors during refreshes.
	ErrColl ErrorCollector

	// Name is the name of this worker.  It is used for logging and error
	// collecting.
	Name string

	// Interval is the refresh interval.  Must be greater than zero.
	Interval time.Duration

	// RefreshOnShutdown, if true, instructs the worker to call the Refresher's
	// Refresh method before shutting down the worker.  This is useful for items
	// that should persist to disk or remote storage before shutting down.
	RefreshOnShutdown bool

	// RoutineLogsAreDebug, if true, instructs the worker to write initial and
	// final log messages for each singular refresh on the Debug level rather
	// than on the Info one.  This is useful to prevent routine logs from
	// workers with a small interval from overflowing with messages.
	RoutineLogsAreDebug bool
}

// NewRefreshWorker returns a new valid *RefreshWorker with the provided
// parameters.  c must not be nil.
func NewRefreshWorker(c *RefreshWorkerConfig) (w *RefreshWorker) {
	// TODO(a.garipov): Add log.WithLevel.
	var logRoutine func(format string, args ...any)
	if c.RoutineLogsAreDebug {
		logRoutine = log.Debug
	} else {
		logRoutine = log.Info
	}

	return &RefreshWorker{
		done:           make(chan unit),
		context:        c.Context,
		logRoutine:     logRoutine,
		tick:           time.NewTicker(c.Interval),
		refr:           c.Refresher,
		errColl:        c.ErrColl,
		name:           c.Name,
		refrOnShutdown: c.RefreshOnShutdown,
	}
}

// Start implements the Service interface for *RefreshWorker.  err is always
// nil.
func (w *RefreshWorker) Start() (err error) {
	go w.refreshInALoop()

	return nil
}

// Shutdown implements the Service interface for *RefreshWorker.
func (w *RefreshWorker) Shutdown(ctx context.Context) (err error) {
	if w.refrOnShutdown {
		err = w.refr.Refresh(ctx)
	}

	close(w.done)

	w.tick.Stop()

	name := w.name
	if err != nil {
		err = fmt.Errorf("refresh on shutdown: %w", err)
		log.Error("%s: shut down with error: %s", name, err)
	} else {
		log.Info("%s: shut down successfully", name)
	}

	return err
}

// refreshInALoop refreshes the entity every tick of w.tick until Shutdown is
// called.
func (w *RefreshWorker) refreshInALoop() {
	name := w.name
	defer log.OnPanic(name)

	log.Info("%s: starting refresh loop", name)

	for {
		select {
		case <-w.done:
			log.Info("%s: finished refresh loop", name)

			return
		case <-w.tick.C:
			w.refresh()
		}
	}
}

// refresh refreshes the entity and logs the status of the refresh.
func (w *RefreshWorker) refresh() {
	name := w.name
	w.logRoutine("%s: refreshing", name)

	// TODO(a.garipov): Consider adding a helper for enriching errors with
	// context deadline data without duplication.  See an example in method
	// filter.refreshableFilter.refresh.
	ctx, cancel := w.context()
	defer cancel()

	log.Debug("%s: starting refresh", name)
	err := w.refr.Refresh(ctx)
	log.Debug("%s: finished refresh", name)

	if err != nil {
		Collectf(ctx, w.errColl, "%s: %w", name, err)

		return
	}

	w.logRoutine("%s: refreshed successfully", name)
}
