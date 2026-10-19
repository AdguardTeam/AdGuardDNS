package tlsconfig

import (
	"net/netip"
	"slices"
)

// prefixSet is a set of [netip.Prefix] based on a sorted slice.
//
// TODO(f.setrakov): Use [container.SortedSliceSet] when it supports
// [netip.Prefix].
type prefixSet struct {
	elems []netip.Prefix
}

// len returns the length of the set.  A nil set has a length of zero.
func (s *prefixSet) len() (res int) {
	if s == nil {
		return 0
	}

	return len(s.elems)
}

// add adds v to set.
func (s *prefixSet) add(v netip.Prefix) {
	idx, ok := slices.BinarySearchFunc(s.elems, v, netip.Prefix.Compare)

	if !ok {
		s.elems = slices.Insert(s.elems, idx, v)
	}
}

// delete removes v from the set.
func (s *prefixSet) delete(v netip.Prefix) {
	idx, ok := slices.BinarySearchFunc(s.elems, v, netip.Prefix.Compare)

	if ok {
		s.elems = slices.Delete(s.elems, idx, idx+1)
	}
}

// values returns a copy of the underlying slice of set.
func (s *prefixSet) values() (prefixes []netip.Prefix) {
	if s == nil {
		return nil
	}

	return slices.Clone(s.elems)
}
