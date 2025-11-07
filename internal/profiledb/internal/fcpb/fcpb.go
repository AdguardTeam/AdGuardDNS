// Package fcpb contains the new opaque api protobuf structures for the profile
// cache.
package fcpb

import (
	"fmt"
	"net/netip"
)

// CIDRRangesToPrefixes is a helper that converts a slice of CidrRange to the
// slice of [netip.Prefix].
func CIDRRangesToPrefixes(cidrs []*CidrRange) (out []netip.Prefix) {
	for _, c := range cidrs {
		addr, ok := netip.AddrFromSlice(c.GetAddress())
		if !ok {
			// Should never happen.
			panic(fmt.Errorf("bad address: %v", c.GetAddress()))
		}

		out = append(out, netip.PrefixFrom(addr, int(c.GetPrefix())))
	}

	return out
}
