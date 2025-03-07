// Package connlimiter describes a limiter of the number of active
// stream-connections.
package connlimiter

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
)

// limitListener is a wrapper that uses a counter to limit the number of active
// stream-connections.
//
// See https://pkg.go.dev/golang.org/x/net/netutil#LimitListener.
type limitListener struct {
	net.Listener

	logger *slog.Logger

	// metrics is used for the collection of the stream connections statistics.
	// It must not be nil.
	metrics Metrics

	// connInfo is used for metrics in both the listener itself and in its
	// conns.  It's never nil.
	connInfo *ConnMetricsData

	// counterCond is the condition variable that protects counter and isClosed
	// through its locker, as well as signals when connections can be accepted
	// again or when the listener has been closed.
	counterCond *sync.Cond

	// counter is the shared counter for all listeners.
	counter *counter

	// isClosed shows whether this listener has been closed.
	isClosed bool
}

// Accept returns a new connection if the counter allows it.  Otherwise, it
// waits until the counter allows it or the listener is closed.
func (l *limitListener) Accept() (conn net.Conn, err error) {
	defer func() { err = errors.Annotate(err, "limit listener: %w") }()

	waitStart := time.Now()

	// TODO(a.garipov):  Find a way to use contexts with Accept.
	ctx := context.Background()
	isClosed := l.increment(ctx)
	if isClosed {
		return nil, net.ErrClosed
	}

	l.metrics.ObserveWaitingDuration(ctx, l.connInfo, time.Since(waitStart))
	l.metrics.IncrementActive(ctx, l.connInfo)

	conn, err = l.Listener.Accept()
	if err != nil {
		l.decrement(ctx)

		return nil, err
	}

	return &limitConn{
		Conn: conn,

		connInfo:  l.connInfo,
		metrics:   l.metrics,
		logger:    l.logger,
		decrement: l.decrement,
		start:     time.Now(),
	}, nil
}

// increment waits until it can increase the number of active connections
// in the counter.  If the listener is closed while waiting, increment exits and
// returns true
func (l *limitListener) increment(ctx context.Context) (isClosed bool) {
	l.counterCond.L.Lock()
	defer l.counterCond.L.Unlock()

	// Make sure to check both that the counter allows this connection and that
	// the listener hasn't been closed.  Only log about waiting for an increment
	// when such waiting actually took place.
	waited := false
	for !l.counter.increment() && !l.isClosed {
		if !waited {
			l.logger.DebugContext(ctx, "accept waiting")

			waited = true
		}

		l.counterCond.Wait()
	}

	if waited {
		l.logger.DebugContext(ctx, "accept stopped waiting")
	}

	return l.isClosed
}

// decrement decreases the number of active connections in the counter and
// broadcasts the change.
func (l *limitListener) decrement(ctx context.Context) {
	defer l.metrics.DecrementActive(ctx, l.connInfo)

	l.counterCond.L.Lock()
	defer l.counterCond.L.Unlock()

	l.counter.decrement()
	l.counterCond.Signal()
}

// Close closes the underlying listener and signals to all goroutines waiting
// for an accept that the listener is closed now.
func (l *limitListener) Close() (err error) {
	defer func() { err = errors.Annotate(err, "limit listener: %w") }()

	l.counterCond.L.Lock()
	defer l.counterCond.L.Unlock()

	if l.isClosed {
		return net.ErrClosed
	}

	// Close the listener immediately; change the boolean and broadcast the
	// change later.
	err = l.Listener.Close()

	l.isClosed = true

	l.counterCond.Broadcast()

	return err
}
