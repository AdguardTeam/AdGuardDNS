package agd

import (
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdvalidate"
	"github.com/AdguardTeam/golibs/errors"
)

// DeviceType is a type of a device as used in the Backend API.
type DeviceType uint8

// DeviceType values.
//
// Do not change the order.  Keep in sync with the Backend API.
const (
	DeviceTypeNone        DeviceType = 0
	DeviceTypeWindows     DeviceType = 1
	DeviceTypeAndroid     DeviceType = 2
	DeviceTypeMacOS       DeviceType = 3
	DeviceTypeIOS         DeviceType = 4
	DeviceTypeLinux       DeviceType = 5
	DeviceTypeRouter      DeviceType = 6
	DeviceTypeSmartTV     DeviceType = 7
	DeviceTypeGameConsole DeviceType = 8
	DeviceTypeOther       DeviceType = 9
)

// deviceTypeStrings is a mapping between a device type and its default string
// representation.  Keep in sync with the DNS API.
var deviceTypeStrings = []string{
	DeviceTypeNone:        "(none)",
	DeviceTypeWindows:     "win",
	DeviceTypeAndroid:     "adr",
	DeviceTypeMacOS:       "mac",
	DeviceTypeIOS:         "ios",
	DeviceTypeLinux:       "lnx",
	DeviceTypeRouter:      "rtr",
	DeviceTypeSmartTV:     "stv",
	DeviceTypeGameConsole: "gam",
	DeviceTypeOther:       "otr",
}

// DeviceTypeFromDNS converts a string into a valid device type.  s is assumed
// to be from a DNS FQDN or HTTP path.  The matching is case-insensitive, and
// "(none)", the string representation of [DeviceTypeNone], is not recognized,
// since it's not a valid type in the DNS API.
func DeviceTypeFromDNS(s string) (dt DeviceType, err error) {
	// Do not use [errors.Annotate] here, because it allocates even when the
	// error is nil.
	defer func() {
		if err != nil {
			err = fmt.Errorf("bad device type %q: %w", s, err)
		}
	}()

	err = agdvalidate.Inclusion(len(s), 3, 3, agdvalidate.UnitByte)
	if err != nil {
		// The error will be wrapped by the deferred helper.
		return DeviceTypeNone, err
	}

	for i, dtStr := range deviceTypeStrings[1:] {
		if strings.EqualFold(s, dtStr) {
			// #nosec G115 -- i is below math.MaxUint8.
			return DeviceType(i + 1), nil
		}
	}

	return DeviceTypeNone, errors.Error("unknown device type")
}

// type check
var _ fmt.Stringer = DeviceTypeNone

// String implements the [fmt.Stringer] interface for DeviceType.
func (dt DeviceType) String() (s string) {
	if int(dt) < len(deviceTypeStrings) {
		return deviceTypeStrings[dt]
	}

	return fmt.Sprintf("!bad_device_type_%d", dt)
}
