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
	// Find returns the profile and device data in ri if it can recognize those.
	// All arguments must not be empty.  A nil result means that the profile and
	// device data could not be found.
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

// DeviceResult is the sum type of the results that can be returned by a
// [DeviceFinder] implementation.
//
// The implementations are:
//
//   - [*DeviceResultAuthenticationFailure]
//   - [*DeviceResultError]
//   - [*DeviceResultOK]
//   - [*DeviceResultUnknownDedicated]
//
// A nil result means that the user data was not found.
type DeviceResult interface {
	isResult()
}

// DeviceResultAuthenticationFailure means that the profile and the device have
// been found, but the device should have been authenticated but could not.  For
// generic errors, see [DeviceResultError].
type DeviceResultAuthenticationFailure struct {
	Err error
}

// type check
var _ DeviceResult = (*DeviceResultAuthenticationFailure)(nil)

// isResult implements the [DeviceResult] interface for
// *DeviceResultAuthenticationFailure.
func (*DeviceResultAuthenticationFailure) isResult() {}

// DeviceResultError is a generic error result.  For authentication errors, see
// [DeviceResultAuthenticationFailure].
type DeviceResultError struct {
	Err error
}

// type check
var _ DeviceResult = (*DeviceResultError)(nil)

// isResult implements the [DeviceResult] interface for *DeviceResultError.
func (*DeviceResultError) isResult() {}

// DeviceResultOK is a successful result that contains the profile and the
// device data.  If the device requires authentication, DeviceResultOK implies
// that the authentication has been successful.  See also
// [DeviceResultAuthenticationFailure].
type DeviceResultOK struct {
	// Device is the device that has been found.  It must not be nil and it must
	// belong to the profile.
	Device *Device

	// Profile is the profile that has been found.  It must not be nil or
	// deleted, and the device must belong to it.
	Profile *Profile
}

// type check
var _ DeviceResult = (*DeviceResultOK)(nil)

// isResult implements the [DeviceResult] interface for *DeviceResultOK.
func (*DeviceResultOK) isResult() {}

// DeviceResultUnknownDedicated means that the request has been made for a
// dedicated IP address with no corresponding profile or device data.  For
// generic errors, see [DeviceResultError].
type DeviceResultUnknownDedicated struct {
	Err error
}

// type check
var _ DeviceResult = (*DeviceResultUnknownDedicated)(nil)

// isResult implements the [DeviceResult] interface for
// *DeviceResultUnknownDedicated.
func (*DeviceResultUnknownDedicated) isResult() {}
