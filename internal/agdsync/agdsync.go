// Package agdsync contains extensions and utilities for package sync from the
// standard library.
//
// TODO(a.garipov): Move to module golibs.
package agdsync

import "sync"

// TypedPool is the strongly typed version of [sync.Pool] that manages pointers
// to T.
type TypedPool[T any] struct {
	pool *sync.Pool
}

// NewTypedPool returns a new strongly typed pool.  newFunc must not be nil.
func NewTypedPool[T any](newFunc func() (v *T)) (p *TypedPool[T]) {
	return &TypedPool[T]{
		pool: &sync.Pool{
			New: func() (v any) { return newFunc() },
		},
	}
}

// Get selects an arbitrary item from the pool, removes it from the pool, and
// returns it to the caller.
//
// See [sync.Pool.Get].
func (p *TypedPool[T]) Get() (v *T) {
	return p.pool.Get().(*T)
}

// Put adds v to the pool.
//
// See [sync.Pool.Put].
func (p *TypedPool[T]) Put(v *T) {
	p.pool.Put(v)
}
