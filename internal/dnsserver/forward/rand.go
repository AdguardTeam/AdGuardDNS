package forward

import (
	cryptorand "crypto/rand"
	"math/rand/v2"
	"sync"
)

// mustNewSeed returns new 32 byte seed for pseudorandom generators.  Panics on
// errors.
//
// TODO(a.garipov):  Remove once agdrand is merged into golibs.
func mustNewSeed() (seed [32]byte) {
	_, err := cryptorand.Read(seed[:])
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		panic(err)
	}

	return seed
}

// lockedSource is an implementation of [rand.Source] that is concurrency-safe.
//
// TODO(a.garipov):  Remove once agdrand is merged into golibs.
type lockedSource struct {
	// mu protects src.
	mu  *sync.Mutex
	src rand.Source
}

// type check
var _ rand.Source = (*lockedSource)(nil)

// Uint64 implements the [rand.Source] interface for *lockedSource.
func (s *lockedSource) Uint64() (r uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.src.Uint64()
}
