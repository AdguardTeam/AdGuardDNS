package filecacheopb

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdprotobuf"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/fcpb"
	"github.com/AdguardTeam/golibs/errors"
)

// devicesFromProtobuf converts protobuf device structures into internal ones.
func devicesFromProtobuf(pbDevices []*fcpb.Device) (devices []*agd.Device, err error) {
	devices = make([]*agd.Device, 0, len(pbDevices))
	for i, pbDev := range pbDevices {
		var dev *agd.Device
		dev, err = deviceToInternal(pbDev)
		if err != nil {
			return nil, fmt.Errorf("device: at index %d: %w", i, err)
		}

		devices = append(devices, dev)
	}

	return devices, nil
}

// deviceToInternal converts a protobuf device structure to an internal one.
// pbDev must not be nil.
func deviceToInternal(pbDev *fcpb.Device) (d *agd.Device, err error) {
	if pbDev == nil {
		panic(fmt.Errorf("pbDev: %w", errors.ErrNoValue))
	}

	var linkedIP netip.Addr
	err = linkedIP.UnmarshalBinary(pbDev.GetLinkedIp())
	if err != nil {
		return nil, fmt.Errorf("linked ip: %w", err)
	}

	var dedicatedIPs []netip.Addr
	dedicatedIPs, err = agdprotobuf.ByteSlicesToIPs(pbDev.GetDedicatedIps())
	if err != nil {
		return nil, fmt.Errorf("dedicated ips: %w", err)
	}

	deviceID := pbDev.GetDeviceId()
	auth, err := authToInternal(pbDev.GetAuthentication())
	if err != nil {
		return nil, fmt.Errorf("auth: %s: %w", deviceID, err)
	}

	return &agd.Device{
		Auth: auth,
		// Consider device IDs to have been prevalidated.
		ID:       agd.DeviceID(deviceID),
		LinkedIP: linkedIP,
		// Consider device names to have been prevalidated.
		Name: agd.DeviceName(pbDev.GetDeviceName()),
		// Consider lowercase HumanIDs to have been prevalidated.
		HumanIDLower:     agd.HumanIDLower(pbDev.GetHumanIdLower()),
		DedicatedIPs:     dedicatedIPs,
		FilteringEnabled: pbDev.GetFilteringEnabled(),
	}, nil
}

// authToInternal converts a protobuf auth settings structure to an internal
// one.  If pbAuth is nil, toInternal returns non-nil settings with Enabled
// field set to false, otherwise it sets the Enabled field to true.
func authToInternal(pbAuth *fcpb.AuthenticationSettings) (s *agd.AuthSettings, err error) {
	if pbAuth == nil {
		return &agd.AuthSettings{
			Enabled:      false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		}, nil
	}

	ph, err := dohPasswordToInternal(pbAuth)
	if err != nil {
		return nil, fmt.Errorf("password hash: %w", err)
	}

	return &agd.AuthSettings{
		PasswordHash: ph,
		Enabled:      true,
		DoHAuthOnly:  pbAuth.GetDohAuthOnly(),
	}, nil
}

// dohPasswordToInternal converts a protobuf DoH password hash sum-type to an
// internal one.  If pbp is nil, it returns nil.
func dohPasswordToInternal(
	pbp *fcpb.AuthenticationSettings,
) (p agdpasswd.Authenticator, err error) {
	switch pbp.WhichDohPasswordHash() {
	case fcpb.AuthenticationSettings_DohPasswordHash_not_set_case:
		return agdpasswd.AllowAuthenticator{}, nil
	case fcpb.AuthenticationSettings_PasswordHashBcrypt_case:
		return agdpasswd.NewPasswordHashBcrypt(pbp.GetPasswordHashBcrypt()), nil
	default:
		return nil, fmt.Errorf("bad pb auth doh password hash %T(%[1]v)", pbp)
	}
}

// devicesToProtobuf converts a slice of devices to protobuf structures.
func devicesToProtobuf(devices []*agd.Device) (pbDevices []*fcpb.Device) {
	pbDevices = make([]*fcpb.Device, 0, len(devices))
	for _, d := range devices {
		pbD := fcpb.Device_builder{
			Authentication:   authToProtobuf(d.Auth),
			DeviceId:         string(d.ID),
			LinkedIp:         agdprotobuf.IPToBytes(d.LinkedIP),
			HumanIdLower:     string(d.HumanIDLower),
			DeviceName:       string(d.Name),
			DedicatedIps:     agdprotobuf.IPsToByteSlices(d.DedicatedIPs),
			FilteringEnabled: d.FilteringEnabled,
		}.Build()

		pbDevices = append(pbDevices, pbD)
	}

	return pbDevices
}

// authToProtobuf converts an auth device settings to a protobuf struct.
// Returns nil if the given settings have Enabled field set to false.
func authToProtobuf(s *agd.AuthSettings) (a *fcpb.AuthenticationSettings) {
	if s == nil || !s.Enabled {
		return nil
	}

	return fcpb.AuthenticationSettings_builder{
		DohAuthOnly:        s.DoHAuthOnly,
		PasswordHashBcrypt: dohPasswordToProtobuf(s.PasswordHash),
	}.Build()
}

// dohPasswordToProtobuf converts an auth password hash sum-type to a protobuf
// one.
func dohPasswordToProtobuf(p agdpasswd.Authenticator) (pbp []byte) {
	switch p := p.(type) {
	case agdpasswd.AllowAuthenticator:
		return nil
	case *agdpasswd.PasswordHashBcrypt:
		return p.PasswordHash()
	default:
		panic(fmt.Errorf("bad password hash %T(%[1]v)", p))
	}
}
