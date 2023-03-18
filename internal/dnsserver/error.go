package dnsserver

import (
	"fmt"
	"net"
	"os"

	"github.com/AdguardTeam/golibs/errors"
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

	// Protocol is either "tcp" or "udp".
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
	if errors.Is(os.ErrDeadlineExceeded, err) {
		return true
	}

	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}
