// Package remotekv contains remote key-value storage interfaces, helpers, and
// implementations.
package remotekv

import (
	"context"
)

// Interface is the remote key-value storage interface.
type Interface interface {
	// Get returns val by key from the storage.  ok is true if val by key
	// exists.
	Get(ctx context.Context, key string) (val []byte, ok bool, err error)

	// Set sets val into the storage by key.
	Set(ctx context.Context, key string, val []byte) (err error)
}

// Empty is the [Interface] implementation that does nothing.
type Empty struct{}

// type check
var _ Interface = Empty{}

// Get implements the [Interface] interface for Empty.  ok is always false.
func (Empty) Get(_ context.Context, _ string) (val []byte, ok bool, err error) {
	return val, false, nil
}

// Set implements the [Interface] interface for Empty.
func (Empty) Set(_ context.Context, _ string, _ []byte) (err error) {
	return nil
}
