package ratelimit

import (
	"sync"
	"time"
)

// Requests Per Second Counter

// rpsCounter is a single request per seconds counter.
type rpsCounter struct {
	// mu protects all fields.
	mu   *sync.Mutex
	ring []int64
	idx  int
}

// newRPSCounter returns a new requests per second counter.  n must be above zero.
func newRPSCounter(n int) (r *rpsCounter) {
	return &rpsCounter{
		mu: &sync.Mutex{},
		// Add one, because we need to always keep track of the previous
		// request.  For example, consider n == 1.
		ring: make([]int64, n+1),
		idx:  0,
	}
}

// add adds another request to the counter.  above is true if the request goes
// above the counter value.  It is safe for concurrent use.
func (r *rpsCounter) add(t time.Time) (above bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ts := t.UnixNano()
	r.ring[r.idx] = ts

	r.idx = (r.idx + 1) % len(r.ring)

	tail := r.ring[r.idx]

	return tail > 0 && ts-tail <= int64(1*time.Second)
}
