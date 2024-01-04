// Package connlimiter describes a limiter of the number of active
// stream-connections.
package connlimiter

import (
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// limitListener is a wrapper that uses a counter to limit the number of active
// stream-connections.
//
// See https://pkg.go.dev/golang.org/x/net/netutil#LimitListener.
type limitListener struct {
	net.Listener

	// serverInfo is used for logging and metrics in both the listener itself
	// and in its conns.  It's never nil.
	serverInfo *dnsserver.ServerInfo

	// counterCond is the condition variable that protects counter and isClosed
	// through its locker, as well as signals when connections can be accepted
	// again or when the listener has been closed.
	counterCond *sync.Cond

	// counter is the shared counter for all listeners.
	counter *counter

	// activeGauge is the metrics gauge of currently active stream-connections.
	activeGauge prometheus.Gauge

	// waitingHist is the metrics histogram of how much a connection spends
	// waiting for an accept.
	waitingHist prometheus.Observer

	// isClosed shows whether this listener has been closed.
	isClosed bool
}

// Accept returns a new connection if the counter allows it.  Otherwise, it
// waits until the counter allows it or the listener is closed.
func (l *limitListener) Accept() (conn net.Conn, err error) {
	defer func() { err = errors.Annotate(err, "limit listener: %w") }()

	waitStart := time.Now()

	isClosed := l.increment()
	if isClosed {
		return nil, net.ErrClosed
	}

	l.waitingHist.Observe(time.Since(waitStart).Seconds())
	l.activeGauge.Inc()

	conn, err = l.Listener.Accept()
	if err != nil {
		l.decrement()

		return nil, err
	}

	return &limitConn{
		Conn: conn,

		decrement:  l.decrement,
		start:      time.Now(),
		serverInfo: l.serverInfo,
	}, nil
}

// increment waits until it can increase the number of active connections
// in the counter.  If the listener is closed while waiting, increment exits and
// returns true
func (l *limitListener) increment() (isClosed bool) {
	l.counterCond.L.Lock()
	defer l.counterCond.L.Unlock()

	// Make sure to check both that the counter allows this connection and that
	// the listener hasn't been closed.  Only log about waiting for an increment
	// when such waiting actually took place.
	waited := false
	for !l.counter.increment() && !l.isClosed {
		if !waited {
			optlog.Debug1("connlimiter: server %s: accept waiting", l.serverInfo.Name)

			waited = true
		}

		l.counterCond.Wait()
	}

	if waited {
		optlog.Debug1("connlimiter: server %s: accept stopped waiting", l.serverInfo.Name)
	}

	return l.isClosed
}

// decrement decreases the number of active connections in the counter and
// broadcasts the change.
func (l *limitListener) decrement() {
	l.counterCond.L.Lock()
	defer l.counterCond.L.Unlock()

	l.activeGauge.Dec()

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
