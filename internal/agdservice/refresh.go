package agdservice

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/timeutil"
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

// RefresherFunc is an adapter to allow the use of ordinary functions as
// [Refresher].
type RefresherFunc func(ctx context.Context) (err error)

// type check
var _ Refresher = RefresherFunc(nil)

// Refresh implements the [Refresher] interface for RefresherFunc.
func (f RefresherFunc) Refresh(ctx context.Context) (err error) {
	return f(ctx)
}

// RefreshWorker is an [Interface] implementation that updates its [Refresher]
// every tick of the provided ticker.
type RefreshWorker struct {
	logger        *slog.Logger
	done          chan unit
	context       func() (ctx context.Context, cancel context.CancelFunc)
	tick          *time.Ticker
	rand          *rand.Rand
	refr          Refresher
	maxStartSleep time.Duration

	refrOnShutdown bool
}

// RefreshWorkerConfig is the configuration structure for a *RefreshWorker.
type RefreshWorkerConfig struct {
	// Context is used to provide a context for the Refresh method of Refresher.
	//
	// NOTE:  It is not used for the shutdown refresh.
	//
	// TODO(a.garipov):  Consider ways of fixing that.
	Context func() (ctx context.Context, cancel context.CancelFunc)

	// Refresher is the entity being refreshed.
	Refresher Refresher

	// Logger is used for logging the operation of the worker.
	Logger *slog.Logger

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
		// #nosec G115 -- The Unix epoch time is highly unlikely to be negative.
		rng = rand.New(rand.NewSource(uint64(time.Now().UnixNano())))
	}

	return &RefreshWorker{
		logger:         c.Logger,
		done:           make(chan unit),
		context:        c.Context,
		tick:           time.NewTicker(c.Interval),
		rand:           rng,
		refr:           c.Refresher,
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
//
// NOTE:  The context provided by [RefreshWorkerConfig.Context] is not used for
// the shutdown refresh.
func (w *RefreshWorker) Shutdown(ctx context.Context) (err error) {
	if w.refrOnShutdown {
		err = w.refr.Refresh(slogutil.ContextWithLogger(ctx, w.logger))
	}

	close(w.done)

	w.tick.Stop()

	if err != nil {
		err = fmt.Errorf("refresh on shutdown: %w", err)
	} else {
		w.logger.InfoContext(ctx, "shut down successfully")
	}

	return err
}

// refreshInALoop refreshes the entity every tick of w.tick until Shutdown is
// called.
func (w *RefreshWorker) refreshInALoop() {
	ctx := context.Background()
	defer slogutil.RecoverAndLog(ctx, w.logger)

	w.logger.InfoContext(ctx, "starting refresh loop")

	for {
		select {
		case <-w.done:
			w.logger.InfoContext(ctx, "finished refresh loop")

			return
		case <-w.tick.C:
			if w.sleepRandom(ctx) {
				w.refresh()
			}
		}
	}
}

// sleepRandom sleeps for up to maxStartSleep unless it's zero.  shouldRefresh
// shows if a refresh should be performed once the sleep is finished.
func (w *RefreshWorker) sleepRandom(ctx context.Context) (shouldRefresh bool) {
	if w.maxStartSleep == 0 {
		return true
	}

	sleepDur := time.Duration(w.rand.Int63n(int64(w.maxStartSleep)))
	// TODO(a.garipov):  Augment our JSON handler to use time.Duration.String
	// automatically?
	w.logger.DebugContext(ctx, "sleeping before refresh", "dur", timeutil.Duration{
		Duration: sleepDur,
	})

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

	ctx = slogutil.ContextWithLogger(ctx, w.logger)

	_ = w.refr.Refresh(ctx)
}

// RefresherWithErrColl reports all refresh errors to errColl and logs them
// using a provided logging function.
type RefresherWithErrColl struct {
	logger  *slog.Logger
	refr    Refresher
	errColl errcoll.Interface
	prefix  string
}

// NewRefresherWithErrColl wraps refr into a refresher that collects errors and
// logs them.
func NewRefresherWithErrColl(
	refr Refresher,
	logger *slog.Logger,
	errColl errcoll.Interface,
	prefix string,
) (wrapped *RefresherWithErrColl) {
	return &RefresherWithErrColl{
		refr:    refr,
		logger:  logger,
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
		errcoll.Collect(ctx, r.errColl, r.logger, "refreshing", err)
	}

	return err
}
