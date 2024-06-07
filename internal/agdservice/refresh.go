package agdservice

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/service"
	"golang.org/x/exp/rand"
)

// Refresher is the interface for entities that can update themselves.
type Refresher interface {
	// Refresh is called by a [RefreshWorker].  The error returned by Refresh is
	// only returned from [RefreshWorker.Shutdown] and only when
	// [RefreshWorkerConfig.RefreshOnShutdown] is true.  In all other cases, the
	// error is ignored, and refreshers must handle error reporting themselves.
	Refresh(ctx context.Context) (err error)
}

// RefreshWorker is an [Interface] implementation that updates its [Refresher]
// every tick of the provided ticker.
type RefreshWorker struct {
	done          chan unit
	context       func() (ctx context.Context, cancel context.CancelFunc)
	tick          *time.Ticker
	rand          *rand.Rand
	refr          Refresher
	name          string
	maxStartSleep time.Duration

	refrOnShutdown bool
}

// RefreshWorkerConfig is the configuration structure for a *RefreshWorker.
type RefreshWorkerConfig struct {
	// Context is used to provide a context for the Refresh method of Refresher.
	Context func() (ctx context.Context, cancel context.CancelFunc)

	// Refresher is the entity being refreshed.
	Refresher Refresher

	// Name is the name of this worker.  It is used for logging and error
	// collecting.
	//
	// TODO(a.garipov): Consider accepting a slog.Logger or removing this and
	// making all Refreshers handle their own logging.
	Name string

	// Interval is the refresh interval.  Must be greater than zero.
	//
	// TODO(a.garipov): Consider switching to an interface à la
	// github.com/robfig/cron/v3.Schedule.
	Interval time.Duration

	// RefreshOnShutdown, if true, instructs the worker to call the Refresher's
	// Refresh method before shutting down the worker.  This is useful for items
	// that should persist to disk or remote storage before shutting down.
	RefreshOnShutdown bool

	// RandomizeStart, if true, instructs the worker to sleep before starting a
	// refresh.  The duration of the sleep is a random duration of up to 10 % of
	// Interval.
	//
	// TODO(a.garipov): Switch to something like a cron schedule and see if this
	// is still necessary
	RandomizeStart bool
}

// NewRefreshWorker returns a new valid *RefreshWorker with the provided
// parameters.  c must not be nil.
func NewRefreshWorker(c *RefreshWorkerConfig) (w *RefreshWorker) {
	var maxStartSleep time.Duration
	var rng *rand.Rand
	if c.RandomizeStart {
		maxStartSleep = c.Interval / 10
		rng = rand.New(rand.NewSource(uint64(time.Now().UnixNano())))
	}

	return &RefreshWorker{
		done:           make(chan unit),
		context:        c.Context,
		tick:           time.NewTicker(c.Interval),
		rand:           rng,
		refr:           c.Refresher,
		name:           c.Name,
		maxStartSleep:  maxStartSleep,
		refrOnShutdown: c.RefreshOnShutdown,
	}
}

// type check
var _ service.Interface = (*RefreshWorker)(nil)

// Start implements the [service.Interface] interface for *RefreshWorker.  err
// is always nil.
func (w *RefreshWorker) Start(_ context.Context) (err error) {
	go w.refreshInALoop()

	return nil
}

// Shutdown implements the [service.Interface] interface for *RefreshWorker.
func (w *RefreshWorker) Shutdown(ctx context.Context) (err error) {
	if w.refrOnShutdown {
		err = w.refr.Refresh(ctx)
	}

	close(w.done)

	w.tick.Stop()

	name := w.name
	if err != nil {
		err = fmt.Errorf("refresh on shutdown: %w", err)
	} else {
		log.Info("worker %q: shut down successfully", name)
	}

	return err
}

// refreshInALoop refreshes the entity every tick of w.tick until Shutdown is
// called.
func (w *RefreshWorker) refreshInALoop() {
	name := w.name
	defer log.OnPanic(name)

	log.Info("worker %q: starting refresh loop", name)

	for {
		select {
		case <-w.done:
			log.Info("worker %q: finished refresh loop", name)

			return
		case <-w.tick.C:
			if w.sleepRandom() {
				w.refresh()
			}
		}
	}
}

// sleepRandom sleeps for up to maxStartSleep unless it's zero.  shouldRefresh
// shows if a refresh should be performed once the sleep is finished.
func (w *RefreshWorker) sleepRandom() (shouldRefresh bool) {
	if w.maxStartSleep == 0 {
		return true
	}

	sleepDur := time.Duration(w.rand.Int63n(int64(w.maxStartSleep)))
	log.Debug("worker %q: sleeping for %s before refresh", w.name, sleepDur)

	timer := time.NewTimer(sleepDur)
	defer func() {
		if !timer.Stop() {
			// We don't know if the timer's value has been consumed yet or not,
			// so use a select with default to make sure that this doesn't
			// block.
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	select {
	case <-w.done:
		return false
	case <-timer.C:
		return true
	}
}

// refresh refreshes the entity and logs the status of the refresh.
func (w *RefreshWorker) refresh() {
	// TODO(a.garipov): Consider adding a helper for enriching errors with
	// context deadline data without duplication.  See an example in method
	// filter.refreshableFilter.refresh.
	ctx, cancel := w.context()
	defer cancel()

	_ = w.refr.Refresh(ctx)
}

// RefresherWithErrColl reports all refresh errors to errColl and logs them
// using a provided logging function.
type RefresherWithErrColl struct {
	refr    Refresher
	log     func(format string, args ...any)
	errColl errcoll.Interface
	prefix  string
}

// NewRefresherWithErrColl wraps refr into a refresher that collects errors and
// logs them.
func NewRefresherWithErrColl(
	refr Refresher,
	logFunc func(format string, args ...any),
	errColl errcoll.Interface,
	prefix string,
) (wrapped *RefresherWithErrColl) {
	return &RefresherWithErrColl{
		refr:    refr,
		log:     logFunc,
		errColl: errColl,
		prefix:  prefix,
	}
}

// type check
var _ Refresher = (*RefresherWithErrColl)(nil)

// Refresh implements the [Refresher] interface for *RefresherWithErrColl.
func (r *RefresherWithErrColl) Refresh(ctx context.Context) (err error) {
	err = r.refr.Refresh(ctx)
	if err != nil {
		err = fmt.Errorf("%s: %w", r.prefix, err)
		r.log("%s", err)
		r.errColl.Collect(ctx, err)
	}

	return err
}
