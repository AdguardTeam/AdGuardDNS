package prometheus

import "sync"

// initSyncMap is a wrapper around [*sync.Map] that initializes the data if it's
// not present in an atomic way.
//
// TODO(a.garipov): Move to golibs and use more.
type initSyncMap[K, V any] struct {
	inner *sync.Map
	new   func(k K) (v V)
}

// newInitSyncMap returns a new properly initialized *initSyncMap that uses
// newFunc to return a value for the given key.
func newInitSyncMap[K, V any](newFunc func(k K) (v V)) (m *initSyncMap[K, V]) {
	return &initSyncMap[K, V]{
		inner: &sync.Map{},
		new:   newFunc,
	}
}

// get returns a value for the given key.  If a value isn't available, it waits
// until it is.
func (m *initSyncMap[K, V]) get(key K) (v V) {
	// Step 1.  The fast track: check if there is already a value present.
	loadVal, inited := m.inner.Load(key)
	if inited {
		return loadVal.(func() (v V))()
	}

	// Step 2.  Allocate a done channel and create a function that waits for one
	// single initialization.  Use the one returned from LoadOrStore regardless
	// of whether it's this one.
	var cached V
	done := make(chan struct{}, 1)
	done <- struct{}{}
	loadVal, _ = m.inner.LoadOrStore(key, func() (loaded V) {
		_, ok := <-done
		if ok {
			// The only real receive.  Initialize the cached value and close the
			// channel so that other goroutines receive the same value.
			cached = m.new(key)
			close(done)
		}

		return cached
	})

	return loadVal.(func() (v V))()
}
