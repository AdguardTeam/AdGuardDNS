package backendpb

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdprotobuf"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/netutil"
)

// devicesToInternal is a helper that converts the devices from protobuf to
// AdGuard DNS devices.
func devicesToInternal(
	ctx context.Context,
	ds []*DeviceSettings,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
	mtrc Metrics,
) (out []*agd.Device, ids []agd.DeviceID) {
	l := len(ds)
	if l == 0 {
		return nil, nil
	}

	out = make([]*agd.Device, 0, l)
	for _, d := range ds {
		dev, err := d.toInternal(bindSet)
		if err != nil {
			var id string
			if d != nil {
				id = d.Id
			}

			reportf(ctx, errColl, "bad device settings for device with id %q: %w", id, err)

			// TODO(s.chzhen):  Add a return result structure and move the
			// metrics collection to the layer above.
			mtrc.IncrementInvalidDevicesCount(ctx)

			continue
		}

		ids = append(ids, dev.ID)
		out = append(out, dev)
	}

	return out, ids
}

// toInternal is a helper that converts device settings from backend protobuf
// response to AdGuard DNS device object.
func (ds *DeviceSettings) toInternal(bindSet netutil.SubnetSet) (dev *agd.Device, err error) {
	if ds == nil {
		return nil, fmt.Errorf("device is nil")
	}

	var linkedIP netip.Addr
	err = linkedIP.UnmarshalBinary(ds.LinkedIp)
	if err != nil {
		return nil, fmt.Errorf("linked ip: %w", err)
	}

	var dedicatedIPs []netip.Addr
	dedicatedIPs, err = ds.dedicatedIPsToInternal(bindSet)
	if err != nil {
		return nil, fmt.Errorf("dedicated ips: %w", err)
	}

	auth, err := ds.Authentication.toInternal()
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	id, err := agd.NewDeviceID(ds.Id)
	if err != nil {
		return nil, fmt.Errorf("device id: %w", err)
	}

	name, err := agd.NewDeviceName(ds.Name)
	if err != nil {
		return nil, fmt.Errorf("device name: %w", err)
	}

	var humanID agd.HumanIDLower
	if humanIDStr := ds.HumanIdLower; humanIDStr != "" {
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
		FilteringEnabled: ds.FilteringEnabled,
	}, nil
}

// dedicatedIPsToInternal converts the dedicated IP data while also validating
// it against the given bindSet.
func (ds *DeviceSettings) dedicatedIPsToInternal(
	bindSet netutil.SubnetSet,
) (dedicatedIPs []netip.Addr, err error) {
	dedicatedIPs, err = agdprotobuf.ByteSlicesToIPs(ds.DedicatedIps)
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
