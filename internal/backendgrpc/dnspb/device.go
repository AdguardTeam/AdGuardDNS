package dnspb

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdprotobuf"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/netutil"
)

// devicesToInternal is a helper that converts the devices from protobuf to
// AdGuard DNS devices.  bindSet, errColl, l, and all elements of pbDevices must
// not be nil.
//
// TODO(a.garipov):  Consider refactoring conversion by using some kind of
// converter struct.
func devicesToInternal(
	ctx context.Context,
	l *slog.Logger,
	pbDevices []*DeviceSettings,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
) (devices []*agd.Device, ids []agd.DeviceID, numBad uint) {
	n := len(pbDevices)
	if n == 0 {
		return nil, nil, 0
	}

	devices = make([]*agd.Device, 0, n)
	for _, pbd := range pbDevices {
		d, err := pbd.ToInternal(bindSet)
		if err != nil {
			err = fmt.Errorf("bad settings for device with id %q: %w", pbd.GetId(), err)
			errcoll.Collect(ctx, errColl, l, "converting device", err)

			numBad++

			continue
		}

		ids = append(ids, d.ID)
		devices = append(devices, d)
	}

	return devices, ids, numBad
}

// ToInternal converts device settings from a backend protobuf response to an
// AdGuard DNS device.  bindSet must not be nil.
func (x *DeviceSettings) ToInternal(bindSet netutil.SubnetSet) (d *agd.Device, err error) {
	if x == nil {
		return nil, fmt.Errorf("device is nil")
	}

	var linkedIP netip.Addr
	err = linkedIP.UnmarshalBinary(x.LinkedIp)
	if err != nil {
		return nil, fmt.Errorf("linked ip: %w", err)
	}

	var dedicatedIPs []netip.Addr
	dedicatedIPs, err = x.dedicatedIPsToInternal(bindSet)
	if err != nil {
		return nil, fmt.Errorf("dedicated ips: %w", err)
	}

	auth, err := x.Authentication.toInternal()
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	id, err := agd.NewDeviceID(x.Id)
	if err != nil {
		return nil, fmt.Errorf("device id: %w", err)
	}

	name, err := agd.NewDeviceName(x.Name)
	if err != nil {
		return nil, fmt.Errorf("device name: %w", err)
	}

	var humanID agd.HumanIDLower
	if humanIDStr := x.HumanIdLower; humanIDStr != "" {
		humanID, err = agd.NewHumanIDLower(humanIDStr)
		if err != nil {
			return nil, fmt.Errorf("lowercase human id: %w", err)
		}
	}

	return &agd.Device{
		Auth:             auth,
		ID:               id,
		Name:             name,
		HumanIDLower:     humanID,
		LinkedIP:         linkedIP,
		DedicatedIPs:     dedicatedIPs,
		FilteringEnabled: x.FilteringEnabled,
	}, nil
}

// dedicatedIPsToInternal converts the dedicated IP data while also validating
// it against the given bindSet.  bintSet must not be nil.
func (x *DeviceSettings) dedicatedIPsToInternal(
	bindSet netutil.SubnetSet,
) (dedicatedIPs []netip.Addr, err error) {
	dedicatedIPs, err = agdprotobuf.ByteSlicesToIPs(x.DedicatedIps)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	// TODO(d.kolyshev): Extract business logic validation.
	for i, addr := range dedicatedIPs {
		if !bindSet.Contains(addr) {
			return nil, fmt.Errorf("at index %d: %q is not in bind data", i, addr)
		}
	}

	return dedicatedIPs, nil
}

// toInternal converts a protobuf auth settings structure to an internal one.
// If x is nil, toInternal returns non-nil settings with enabled field set to
// false.
func (x *AuthenticationSettings) toInternal() (s *agd.AuthSettings, err error) {
	if x == nil {
		return &agd.AuthSettings{
			Enabled:      false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		}, nil
	}

	ph, err := dohPasswordToInternal(x.DohPasswordHash)
	if err != nil {
		return nil, fmt.Errorf("password hash: %w", err)
	}

	return &agd.AuthSettings{
		PasswordHash: ph,
		Enabled:      true,
		DoHAuthOnly:  x.DohAuthOnly,
	}, nil
}

// dohPasswordToInternal converts a protobuf DoH password hash sum-type to an
// internal one.
func dohPasswordToInternal(
	pbp isAuthenticationSettings_DohPasswordHash,
) (p agdpasswd.Authenticator, err error) {
	switch pbp := pbp.(type) {
	case nil:
		return agdpasswd.AllowAuthenticator{}, nil
	case *AuthenticationSettings_PasswordHashBcrypt:
		return agdpasswd.NewPasswordHashBcrypt(pbp.PasswordHashBcrypt), nil
	default:
		return nil, fmt.Errorf("bad pb auth doh password hash %T(%[1]v)", pbp)
	}
}
