//go:build linux

package bindtodevice

import (
	"fmt"
	"net/netip"

	"golang.org/x/exp/slices"
)

// connIndex is the data structure that contains the channel listeners and
// packet connections, to which the [Manager] sends new connections and packets
// based on their protocol (TCP vs. UDP), and subnet.
//
// In both slices a subnet with the largest prefix (the narrowest subnet) is
// sorted closer to the beginning.
type connIndex struct {
	packetConns []*chanPacketConn
	listeners   []*chanListener
}

// subnetCompare is a comparison function for the two subnets.  It returns -1 if
// x sorts before y, 1 if x sorts after y, and 0 if their relative sorting
// position is the same.
func subnetCompare(x, y netip.Prefix) (cmp int) {
	if x == y {
		return 0
	}

	xAddr, xBits := x.Addr(), x.Bits()
	yAddr, yBits := y.Addr(), y.Bits()
	if xBits == yBits {
		return xAddr.Compare(yAddr)
	}

	if xBits > yBits {
		return -1
	} else {
		return 1
	}
}

// addPacketConn adds the channel packet connection to the index.  It returns an
// error if there is already one for this subnet.  c.subnet should be masked.
//
// TODO(a.garipov): Merge with [addListenerChannel].
func (idx *connIndex) addPacketConn(c *chanPacketConn) (err error) {
	cmpFunc := func(x, y *chanPacketConn) (cmp int) {
		return subnetCompare(x.subnet, y.subnet)
	}

	newIdx, ok := slices.BinarySearchFunc(idx.packetConns, c, cmpFunc)
	if ok {
		return fmt.Errorf("packetconn channel for subnet %s already registered", c.subnet)
	}

	// TODO(a.garipov): Consider using a list for idx.packetConns.  Currently,
	// len(listeners) is small enough for O(n) to not matter, and this method is
	// only actively called during initialization anyway.
	idx.packetConns = slices.Insert(idx.packetConns, newIdx, c)

	return nil
}

// addListener adds the channel listener to the index.  It returns an error if
// there is already one for this subnet.  l.subnet should be masked.
//
// TODO(a.garipov): Merge with [addPacketConnChannel].
func (idx *connIndex) addListener(l *chanListener) (err error) {
	cmpFunc := func(x, y *chanListener) (cmp int) {
		return subnetCompare(x.subnet, y.subnet)
	}

	newIdx, ok := slices.BinarySearchFunc(idx.listeners, l, cmpFunc)
	if ok {
		return fmt.Errorf("listener channel for subnet %s already registered", l.subnet)
	}

	// TODO(a.garipov): Consider using a list for idx.listeners.  Currently,
	// len(listeners) is small enough for O(n) to not matter, and this method is
	// only actively called during initialization anyway.
	idx.listeners = slices.Insert(idx.listeners, newIdx, l)

	return nil
}

// packetConn returns a channel packet connection which accepts connections to
// local address laddr or nil if there is no such channel
func (idx *connIndex) packetConn(laddr netip.Addr) (c *chanPacketConn) {
	for _, c = range idx.packetConns {
		if c.subnet.Contains(laddr) {
			return c
		}
	}

	return nil
}

// listener returns a channel listener which accepts connections to local
// address laddr or nil if there is no such channel
func (idx *connIndex) listener(laddr netip.Addr) (l *chanListener) {
	for _, l = range idx.listeners {
		if l.subnet.Contains(laddr) {
			return l
		}
	}

	return nil
}
