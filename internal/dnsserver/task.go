package dnsserver

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/panjf2000/ants/v2"
)

// task is a function that is intended to be used as a goroutine in a
// [taskPool].
type task func()

// taskPool is a wrapper around [ants.Pool] with convenience methods for using
// it with [sync.WaitGroup]s.
type taskPool struct {
	ants.Pool
}

// taskPoolConfig is the configuration for a [taskPool].
type taskPoolConfig struct {
	// logger is used for logging the operation of the task pool.  It must not
	// be nil.
	logger *slog.Logger
}

// mustNewTaskPool creates a new properly initialized *taskPool configured
// optimally for using it in DNS servers.  It panics if there are errors.
// c must not be nil and must be valid.
func mustNewTaskPool(c *taskPoolConfig) (p *taskPool) {
	pool, err := ants.NewPool(0, ants.WithOptions(ants.Options{
		ExpiryDuration: time.Minute,
		PreAlloc:       false,
		Nonblocking:    true,
		DisablePurge:   false,
		Logger: &antsLogger{
			logger: c.logger,
		},
	}))
	errors.Check(err)

	return &taskPool{
		Pool: *pool,
	}
}

// submitWG is a convenience method that submits t to the pool and accounts
// for it in wg.  All arguments must not be nil.
func (p *taskPool) submitWG(wg *sync.WaitGroup, t task) (err error) {
	wg.Add(1)

	err = p.Submit(func() {
		defer wg.Done()

		t()
	})
	if err != nil {
		// Decrease the counter if the goroutine hasn't been started.
		wg.Done()
	}

	return err
}

// antsLogger implements the [ants.Logger] interface and writes everything
// to its logger.
type antsLogger struct {
	logger *slog.Logger
}

// type check
var _ ants.Logger = (*antsLogger)(nil)

// Printf implements the [ants.Logger] interface for *antsLogger.
func (l *antsLogger) Printf(format string, args ...any) {
	l.logger.Info("ants pool", slogutil.KeyMessage, fmt.Sprintf(format, args...))
}
