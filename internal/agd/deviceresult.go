package agd

// DeviceResult is the sum type of the results that can be returned by a
// [DeviceFinder] implementation.
//
// The possible underlying types are:
//
//   - nil
//   - [*DeviceResultAuthenticationFailure]
//   - [*DeviceResultError]
//   - [*DeviceResultOK]
//   - [*DeviceResultPartialData]
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

// DeviceResultPartialData means that the request has been made for which only
// partial data could be recognized.  For example, only its account or profile
// record but not the device itself.
type DeviceResultPartialData struct {
	// IsAccountIP is true if the request has been made to an Account-wide IP
	// address.
	IsAccountIP bool
}

// type check
var _ DeviceResult = (*DeviceResultPartialData)(nil)

// isResult implements the [DeviceResult] interface for
// *DeviceResultPartialData.
func (*DeviceResultPartialData) isResult() {}

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
