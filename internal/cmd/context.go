package cmd

import (
	"context"
	"time"
)

// defaultTimeout is the timeout used for some operations where another timeout
// hasn't been defined yet.
const defaultTimeout = 30 * time.Second

// contextConstructor is a type alias for functions that can create a context.
type contextConstructor = func() (ctx context.Context, cancel context.CancelFunc)

// ctxWithDefaultTimeout is a helper function that returns a context with
// timeout set to defaultTimeout.
func ctxWithDefaultTimeout() (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultTimeout)
}

// newCtxWithTimeoutCons returns a context constructor that creates a simple
// context with the given timeout.
func newCtxWithTimeoutCons(timeout time.Duration) (c contextConstructor) {
	parent := context.Background()

	return func() (ctx context.Context, cancel context.CancelFunc) {
		return context.WithTimeout(parent, timeout)
	}
}
