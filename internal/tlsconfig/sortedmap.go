package tlsconfig

import (
	"cmp"
	"slices"
)

// sortedMap is a map that keeps elements in order with internal sorting
// function.  It must be initialized with [newSortedMap].
//
// TODO(e.burkov):  Move to golibs.
type sortedMap[K comparable, V any] struct {
	vals map[K]V
	cmp  func(a, b K) (res int)
	keys []K
}

// newSortedMap initializes a new instance of sorted map.
func newSortedMap[K cmp.Ordered, V any]() (m *sortedMap[K, V]) {
	return &sortedMap[K, V]{
		vals: map[K]V{},
		cmp:  cmp.Compare[K],
	}
}

// set adds val with key to the sorted map.  It panics if the m is nil.
func (m *sortedMap[K, V]) set(key K, val V) {
	m.vals[key] = val

	i, has := slices.BinarySearchFunc(m.keys, key, m.cmp)
	if has {
		m.keys[i] = key
	} else {
		m.keys = slices.Insert(m.keys, i, key)
	}
}

// get returns val by key from the sorted map.
func (m *sortedMap[K, V]) get(key K) (val V, ok bool) {
	if m == nil {
		var zero V

		return zero, false
	}

	val, ok = m.vals[key]

	return val, ok
}

// del removes the value by key from the sorted map.
func (m *sortedMap[K, V]) del(key K) {
	if m == nil {
		return
	}

	if _, has := m.vals[key]; !has {
		return
	}

	delete(m.vals, key)
	i, _ := slices.BinarySearchFunc(m.keys, key, m.cmp)
	m.keys = slices.Delete(m.keys, i, i+1)
}

// clear removes all elements from the sorted map.
func (m *sortedMap[K, V]) clear() {
	if m == nil {
		return
	}

	m.keys = m.keys[:0]
	clear(m.vals)
}

// rangeFn calls f for each element of the map, sorted by m.cmp.  If f returns
// false it stops.
func (m *sortedMap[K, V]) rangeFn(f func(K, V) (cont bool)) {
	if m == nil {
		return
	}

	for _, k := range m.keys {
		if !f(k, m.vals[k]) {
			return
		}
	}
}

// len returns the number of elements in the sorted map.
func (m *sortedMap[K, V]) len() (n int) {
	if m == nil {
		return 0
	}

	return len(m.vals)
}
