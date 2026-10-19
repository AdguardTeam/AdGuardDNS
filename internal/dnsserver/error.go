package dnsserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// Common Errors And Error Helpers

const (
	// ErrServerAlreadyStarted signals that server has been already started
	// Can be returned by Server.ListenAndServe.
	ErrServerAlreadyStarted errors.Error = "dnsserver: server already started"

	// ErrServerNotStarted signals that server has been already stopped
	// Can be returned by Server.Shutdown.
	ErrServerNotStarted errors.Error = "dnsserver: server not started"

	// ErrInvalidArgument signals that the argument passed to the function
	// is not valid.
	ErrInvalidArgument errors.Error = "dnsserver: invalid argument"

	// ErrProtocol signals that the DNS message violates the protocol.
	ErrProtocol errors.Error = "dnsserver: protocol error"
)

// WriteError is returned from WriteMsg.
type WriteError struct {
	// Err is the underlying error.
	Err error

	// Protocol is one of the following:
	//   - "quic",
	//   - "tcp",
	//   - "udp".
	Protocol string
}

// type check
var _ error = (*WriteError)(nil)

// Error implements the error interface for *WriteError.
func (err *WriteError) Error() (msg string) {
	return fmt.Sprintf("%s: writing message: %s", err.Protocol, err.Err)
}

// type check
var _ errors.Wrapper = (*WriteError)(nil)

// Unwrap implements the errors.Wrapper interface for *WriteError.
func (err *WriteError) Unwrap() (unwrapped error) {
	return err.Err
}

// isNonCriticalNetError is a helper that returns true if err is a net.Error and
// its Timeout method returns true.
//
// TODO(ameshkov): Replace this code with more precise error handling in each
// case.  It seems like all places where this function is used should detect
// precise error conditions for exiting a loop instead of this.
func isNonCriticalNetError(err error) (ok bool) {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	netErr, ok := errors.AsType[net.Error](err)

	return ok && netErr.Timeout()
}

// closeWithLog closes c and logs a debug message if c.Close returns an error
// that isn't [net.ErrClosed].
//
// TODO(a.garipov):  Unify error handling with regards to [io.EOF],
// net.ErrClosed, etc.
func closeWithLog(ctx context.Context, l *slog.Logger, msg string, c io.Closer) {
	err := c.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		l.DebugContext(ctx, msg, slogutil.KeyError, err)
	}
}

// callOnError calls f if recovered or err is not nil.  Additionally, if
// recovered is not nil, it repanics.  f must not be nil.
//
// TODO(a.garipov):  Consider moving to golibs.
func callOnError(f func(), recovered any, err error) {
	panicked := recovered != nil
	if panicked || err != nil {
		f()
	}

	if panicked {
		panic(recovered)
	}
}

// closeOnError closes c if recovered or err is not nil.  Additionally, if
// recovered is not nil, it repanics.  l is used to log the error from c.Close.
// l and c must not be nil.
func closeOnError(ctx context.Context, l *slog.Logger, c io.Closer, recovered any, err error) {
	f := func() {
		closeErr := c.Close()
		if closeErr != nil {
			l.DebugContext(ctx, "deferred closing", slogutil.KeyError, closeErr)
		}
	}

	callOnError(f, recovered, err)
}
