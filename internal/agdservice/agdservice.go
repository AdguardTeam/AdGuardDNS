// Package agdservice defines types and interfaces for long-running services.
//
// TODO(a.garipov): Move to golibs.
package agdservice

import "context"

// Interface is the interface for long-running services.
//
// TODO(a.garipov): Define whether or not a service should finish starting or
// shutting down before returning from these methods.
type Interface interface {
	// Start starts the service.  ctx is used for cancelation.
	//
	// TODO(a.garipov): Use contexts with timeouts everywhere.
	Start(ctx context.Context) (err error)

	// Shutdown gracefully stops the service.  ctx is used to determine
	// a timeout before trying to stop the service less gracefully.
	//
	// TODO(a.garipov): Use contexts with timeouts everywhere.
	Shutdown(ctx context.Context) (err error)
}

// type check
var _ Interface = Empty{}

// Empty is an [Interface] implementation that does nothing.
type Empty struct{}

// Start implements the [Interface] interface for Empty.
func (Empty) Start(_ context.Context) (err error) { return nil }

// Shutdown implements the [Interface] interface for Empty.
func (Empty) Shutdown(_ context.Context) (err error) { return nil }

// unit is a convenient alias for struct{}.
type unit = struct{}
