package agd

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

// DeviceFinder finds the user data, such as the profile and a device for a
// request.
//
// TODO(a.garipov):  Move device-related stuff to agddevice.
type DeviceFinder interface {
	// Find returns the account, profile, and/or device data in ri if it can
	// recognize any of them at least partially.  A nil result means that no
	// device-related data could be found.  All arguments must not be empty.
	Find(ctx context.Context, req *dns.Msg, raddr, laddr netip.AddrPort) (r DeviceResult)
}

// EmptyDeviceFinder is an [DeviceFinder] implementation that does nothing.
type EmptyDeviceFinder struct{}

// type check
var _ DeviceFinder = EmptyDeviceFinder{}

// Find implements the [DeviceFinder] interface for EmptyDeviceFinder.  It does
// nothing and returns nil.
func (EmptyDeviceFinder) Find(_ context.Context, _ *dns.Msg, _, _ netip.AddrPort) (r DeviceResult) {
	return nil
}
