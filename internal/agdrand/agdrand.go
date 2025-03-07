// Package agdrand contains utilities for random numbers.
//
// TODO(a.garipov): Move to golibs.
package agdrand

import (
	cryptorand "crypto/rand"
	"math/rand/v2"
	"sync"
)

// Reader is a ChaCha8-based cryptographically strong random number reader.
// It's safe for concurrent use.
type Reader struct {
	// mu protects reader.
	mu *sync.Mutex

	reader *rand.ChaCha8
}

// NewReader returns a new properly initialized *Reader seeded with the given
// seed.
func NewReader(seed [32]byte) (r *Reader) {
	return &Reader{
		mu:     &sync.Mutex{},
		reader: rand.NewChaCha8(seed),
	}
}

// Read generates len(p) random bytes and writes them into p.  It always returns
// len(p) and a nil error.  It's safe for concurrent use.
func (r *Reader) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.reader.Read(p)
}

// LockedSource is an implementation of [rand.Source] that is concurrency-safe.
type LockedSource struct {
	// mu protects src.
	mu *sync.Mutex

	src rand.Source
}

// NewLockedSource returns new properly initialized *LockedSource.
func NewLockedSource(src rand.Source) (s *LockedSource) {
	return &LockedSource{
		mu:  &sync.Mutex{},
		src: src,
	}
}

// type check
var _ rand.Source = (*LockedSource)(nil)

// Uint64 implements the [rand.Source] interface for *LockedSource.
func (s *LockedSource) Uint64() (r uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.src.Uint64()
}

// MustNewSeed returns new 32 byte seed for pseudorandom generators.  Panics on
// errors.
func MustNewSeed() (seed [32]byte) {
	_, err := cryptorand.Read(seed[:])
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		panic(err)
	}

	return seed
}
