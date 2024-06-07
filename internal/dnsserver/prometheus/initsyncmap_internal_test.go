package prometheus

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestInitSyncMap(t *testing.T) {
	numCalls := atomic.Uint32{}
	m := newInitSyncMap(func(k int) (v int) {
		numCalls.Add(1)

		return k + 1
	})

	const (
		n = 1_000

		key  = 1
		want = key + 1
	)

	results := make(chan int, n)

	for range n {
		go func() {
			results <- m.get(key)
		}()
	}

	for range n {
		got, _ := testutil.RequireReceive(t, results, 1*time.Second)
		assert.Equal(t, want, got)
	}

	assert.Equal(t, uint32(1), numCalls.Load())
}
