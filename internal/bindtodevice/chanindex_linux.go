//go:build linux

package bindtodevice

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/exp/slices"
)

// chanIndex is the data structure that contains the channels, to which the
// [Manager] sends new connections and packets based on their protocol (TCP vs.
// UDP), and subnet.
//
// In both slices a subnet with the largest prefix (the narrowest subnet) is
// sorted closer to the beginning.
type chanIndex struct {
	packetConns []*indexPacketConn
	listeners   []*indexListener
}

// indexPacketConn contains data of a [chanPacketConn] in the index.
type indexPacketConn struct {
	channel chan *packetSession
	subnet  netip.Prefix
}

// indexListener contains data of a [chanListener] in the index.
type indexListener struct {
	channel chan net.Conn
	subnet  netip.Prefix
}

// subnetSortsBefore returns true if subnet x sorts before subnet y.
func subnetSortsBefore(x, y netip.Prefix) (isBefore bool) {
	xAddr, xBits := x.Addr(), x.Bits()
	yAddr, yBits := y.Addr(), y.Bits()
	if xBits == yBits {
		return xAddr.Less(yAddr)
	}

	return xBits > yBits
}

// subnetCompare is a comparison function for the two subnets.  It returns -1 if
// x sorts before y, 1 if x sorts after y, and 0 if their relative sorting
// position is the same.
func subnetCompare(x, y netip.Prefix) (cmp int) {
	switch {
	case x == y:
		return 0
	case subnetSortsBefore(x, y):
		return -1
	default:
		return 1
	}
}

// addPacketConnChannel adds the channel to the subnet index.  It returns an
// error if there is already one for this subnet.  subnet should be masked.
//
// TODO(a.garipov): Merge with [addListenerChannel].
func (idx *chanIndex) addPacketConnChannel(
	subnet netip.Prefix,
	ch chan *packetSession,
) (err error) {
	c := &indexPacketConn{
		channel: ch,
		subnet:  subnet,
	}

	cmpFunc := func(x, y *indexPacketConn) (cmp int) {
		return subnetCompare(x.subnet, y.subnet)
	}

	newIdx, ok := slices.BinarySearchFunc(idx.packetConns, c, cmpFunc)
	if ok {
		return fmt.Errorf("packetconn channel for subnet %s already registered", subnet)
	}

	// TODO(a.garipov): Consider using a list for idx.packetConns.  Currently,
	// len(listeners) is small enough for O(n) to not matter, and this method is
	// only actively called during initialization anyway.
	idx.packetConns = slices.Insert(idx.packetConns, newIdx, c)

	return nil
}

// addListenerChannel adds the channel to the subnet index.  It returns an error
// if there is already one for this subnet.  subnet should be masked.
//
// TODO(a.garipov): Merge with [addPacketConnChannel].
func (idx *chanIndex) addListenerChannel(subnet netip.Prefix, ch chan net.Conn) (err error) {
	l := &indexListener{
		channel: ch,
		subnet:  subnet,
	}

	cmpFunc := func(x, y *indexListener) (cmp int) {
		return subnetCompare(x.subnet, y.subnet)
	}

	newIdx, ok := slices.BinarySearchFunc(idx.listeners, l, cmpFunc)
	if ok {
		return fmt.Errorf("listener channel for subnet %s already registered", subnet)
	}

	// TODO(a.garipov): Consider using a list for idx.listeners.  Currently,
	// len(listeners) is small enough for O(n) to not matter, and this method is
	// only actively called during initialization anyway.
	idx.listeners = slices.Insert(idx.listeners, newIdx, l)

	return nil
}

// packetConnChannel returns a packet-connection channel which accepts
// connections to local address laddr or nil if there is no such channel
func (idx *chanIndex) packetConnChannel(laddr netip.Addr) (ch chan *packetSession) {
	for _, c := range idx.packetConns {
		if c.subnet.Contains(laddr) {
			return c.channel
		}
	}

	return nil
}

// listenerChannel returns a listener channel which accepts connections to local
// address laddr or nil if there is no such channel
func (idx *chanIndex) listenerChannel(laddr netip.Addr) (ch chan net.Conn) {
	for _, l := range idx.listeners {
		if l.subnet.Contains(laddr) {
			return l.channel
		}
	}

	return nil
}
