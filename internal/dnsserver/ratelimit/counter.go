package ratelimit

import (
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/container"
)

// RequestCounter is a single request-per-interval counter.
//
// TODO(a.garipov):  Add clock inteface.
type RequestCounter struct {
	// mu protects all fields.
	mu *sync.Mutex

	// ring is a container with requests records.  It is never nil.
	ring *container.RingBuffer[int64]

	// ivl is a time duration in which the requests are counted.
	ivl time.Duration
}

// NewRequestCounter returns a new requests-per-interval counter.
func NewRequestCounter(num uint, ivl time.Duration) (r *RequestCounter) {
	return &RequestCounter{
		mu: &sync.Mutex{},
		// Add one, because we need to always keep track of the previous
		// request.  For example, consider num == 1.
		ring: container.NewRingBuffer[int64](num + 1),
		ivl:  ivl,
	}
}

// Add adds another request to r.  isAbove is true if the request goes above the
// counter value.  It is safe for concurrent use.
func (r *RequestCounter) Add(t time.Time) (isAbove bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ts := t.UnixNano()

	r.ring.Push(ts)
	tail := r.ring.Current()

	return tail > 0 && ts-tail <= int64(1*r.ivl)
}
