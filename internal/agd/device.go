package agd

import (
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
)

// Device is a device of a device attached to a profile.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
type Device struct {
	// Auth defines authentication settings of this device.  It's never nil.
	Auth *AuthSettings

	// ID is the unique ID of the device.
	ID DeviceID

	// LinkedIP, when non-empty, allows AdGuard DNS to identify a device by its
	// IP address when it can only use plain DNS.
	LinkedIP netip.Addr

	// Name is the human-readable name of the device.
	Name DeviceName

	// HumanIDLower is the lower-case version of the normalized [HumanID] used
	// to create this device, if any.
	HumanIDLower HumanIDLower

	// DedicatedIPs are the destination (server) IP-addresses dedicated to this
	// device, if any.  A device can use one of these addresses as a DNS server
	// address for AdGuard DNS to recognize it.
	DedicatedIPs []netip.Addr

	// FilteringEnabled defines whether queries from the device should be
	// filtered in any way at all.
	FilteringEnabled bool
}

// DeviceID is the ID of a device attached to a profile.  It is an opaque
// string.
type DeviceID string

// The maximum and minimum lengths of a device ID.
const (
	MaxDeviceIDLen = 8
	MinDeviceIDLen = 1
)

// NewDeviceID converts a simple string into a DeviceID and makes sure that it's
// valid.  This should be preferred to a simple type conversion.
func NewDeviceID(s string) (id DeviceID, err error) {
	// Do not use errors.Annotate here, because it allocates even when the error
	// is nil.
	//
	// TODO(a.garipov): Find out, why does it allocate and perhaps file an
	// issue about that in the Go issue tracker.
	defer func() {
		if err != nil {
			err = fmt.Errorf("bad device id %q: %w", s, err)
		}
	}()

	err = ValidateInclusion(len(s), MaxDeviceIDLen, MinDeviceIDLen, UnitByte)
	if err != nil {
		// The error will be wrapped by the deferred helper.
		return "", err
	}

	err = netutil.ValidateHostnameLabel(s)
	if err != nil {
		// Unwrap the error to replace the domain name label wrapper message
		// with our own.
		return "", errors.Unwrap(err)
	}

	return DeviceID(s), nil
}

// DeviceName is the human-readable name of a device attached to a profile.
type DeviceName string

// MaxDeviceNameRuneLen is the maximum length of a human-readable device name in
// runes.
const MaxDeviceNameRuneLen = 128

// NewDeviceName converts a simple string into a DeviceName and makes sure that
// it's valid.  This should be preferred to a simple type conversion.
func NewDeviceName(s string) (n DeviceName, err error) {
	// Do not use errors.Annotate here, because it allocates even when the error
	// is nil.
	//
	// TODO(a.garipov): Same as the TODO in NewDeviceID.
	defer func() {
		if err != nil {
			err = fmt.Errorf("bad device name %q: %w", s, err)
		}
	}()

	err = ValidateInclusion(utf8.RuneCountInString(s), MaxDeviceNameRuneLen, 0, UnitRune)
	if err != nil {
		// The error will be wrapped by the deferred helper.
		return "", err
	}

	return DeviceName(s), nil
}

// AuthSettings are the authentication settings of a device.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
type AuthSettings struct {
	// PasswordHash is the hash of the auth password.  It is never nil.
	PasswordHash agdpasswd.Authenticator

	// Enabled tells whether the authentication should be enabled at all.
	// This must be true in order for all parameters to work.
	Enabled bool

	// DoHAuthOnly defines if the device should only be authenticated through
	// DoH protocol.
	DoHAuthOnly bool
}
