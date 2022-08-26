// Package querylog defines the AdGuard DNS query log constants and types and
// provides implementations of the log.
package querylog

import (
	"context"
)

// Common Constants, Functions, And Types

// Interface is the query log interface.  All methods must be safe for
// concurrent use.
type Interface interface {
	// Write writes the entry into the query log.  e must not be nil.
	Write(ctx context.Context, e *Entry) (err error)
}

// Empty is a query log does nothing and returns nil values.
type Empty struct{}

// type check
var _ Interface = Empty{}

// Write implements the Interface interface for Empty.  It does nothing and
// returns nil.
func (Empty) Write(_ context.Context, _ *Entry) (err error) {
	return nil
}
