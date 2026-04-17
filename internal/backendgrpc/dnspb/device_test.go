package dnspb_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

var (
	// testAddr is test IPv4 localhost address for tests.
	testAddr = netutil.IPv4Localhost()

	// testDeviceName is a 128-length string representing a valid device name.
	testDeviceName = strings.Repeat("x", 128)
)

func TestDeviceSettings_ToInternal(t *testing.T) {
	t.Parallel()

	passwordHash := []byte("password_hash")
	bcryptAuthSettings := &dnspb.AuthenticationSettings{
		DohPasswordHash: &dnspb.AuthenticationSettings_PasswordHashBcrypt{
			PasswordHashBcrypt: passwordHash,
		},
	}

	testCases := []struct {
		settings   *dnspb.DeviceSettings
		want       *agd.Device
		bindSet    netutil.SubnetSet
		name       string
		wantErrMsg string
	}{{
		name: "success",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
			Id:           backendtest.DeviceIDStr,
			Name:         testDeviceName,
			HumanIdLower: backendtest.HumanIDLowerStr,
		},
		bindSet: backendtest.Bind,
		want: &agd.Device{
			Auth: &agd.AuthSettings{
				PasswordHash: agdpasswd.AllowAuthenticator{},
				Enabled:      false,
			},
			ID:           backendtest.DeviceID,
			LinkedIP:     testAddr,
			DedicatedIPs: []netip.Addr{testAddr},
			Name:         agd.DeviceName(testDeviceName),
			HumanIDLower: backendtest.HumanIDLowerStr,
		},
		wantErrMsg: "",
	}, {
		name: "success_bcrypt_hash",
		settings: &dnspb.DeviceSettings{
			Authentication: bcryptAuthSettings,
			LinkedIp:       testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
			Id:           backendtest.DeviceIDStr,
			Name:         testDeviceName,
			HumanIdLower: backendtest.HumanIDLowerStr,
		},
		bindSet: backendtest.Bind,
		want: &agd.Device{
			Auth: &agd.AuthSettings{
				PasswordHash: agdpasswd.NewPasswordHashBcrypt(passwordHash),
				Enabled:      true,
			},
			ID:           backendtest.DeviceID,
			LinkedIP:     testAddr,
			DedicatedIPs: []netip.Addr{testAddr},
			Name:         agd.DeviceName(testDeviceName),
			HumanIDLower: backendtest.HumanIDLowerStr,
		},
		wantErrMsg: "",
	}, {
		name:       "nil_receiver",
		settings:   nil,
		wantErrMsg: "device is nil",
		bindSet:    backendtest.Bind,
		want:       nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.settings.ToInternal(tc.bindSet)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDeviceSettings_ToInternal_deviceErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		settings   *dnspb.DeviceSettings
		want       *agd.Device
		bindSet    netutil.SubnetSet
		name       string
		wantErrMsg string
	}{{
		name: "bad_device_id_too_short",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
			Id: "",
		},
		bindSet:    backendtest.Bind,
		wantErrMsg: `device id: bad device id "": too short: got 0 bytes, min 1`,
	}, {
		name: "bad_device_id_too_long",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
			Id: "111122223",
		},
		bindSet:    backendtest.Bind,
		wantErrMsg: `device id: bad device id "111122223": too long: got 9 bytes, max 8`,
	}, {
		name: "bad_device_id_too_long",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
			Id:   backendtest.DeviceIDStr,
			Name: testDeviceName + "x",
		},
		bindSet: backendtest.Bind,
		wantErrMsg: `device name: bad device name "` + testDeviceName +
			`x` + `": too long: got 129 runes, max 128`,
	}, {
		name: "invalid_linked_ip",
		settings: &dnspb.DeviceSettings{
			LinkedIp: []byte("1234abcd"),
		},
		wantErrMsg: "linked ip: unexpected slice size",
		bindSet:    backendtest.Bind,
		want:       nil,
	}, {
		name: "invalid_dedicated_ips",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				[]byte("1234abcd"),
			},
		},
		wantErrMsg: "dedicated ips: ip at index 0: unexpected slice size",
	}, {
		name: "dedicated_ips_not_in_bind_data",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
		},
		bindSet:    netip.Prefix{},
		wantErrMsg: `dedicated ips: at index 0: "127.0.0.1" is not in bind data`,
	}, {
		name: "bad_human_id_not_lowercase",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
			Id:           backendtest.DeviceIDStr,
			Name:         testDeviceName,
			HumanIdLower: "A",
		},
		bindSet: backendtest.Bind,
		wantErrMsg: `lowercase human id: bad lowercase human id "A": ` +
			`at index 0: 'A' is not lowercase`,
	}, {
		name: "bad_human_id_bad_label_rune",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
			Id:           backendtest.DeviceIDStr,
			Name:         testDeviceName,
			HumanIdLower: "-",
		},
		bindSet: backendtest.Bind,
		wantErrMsg: `lowercase human id: bad lowercase human id "-": bad ` +
			`hostname label "-": bad hostname label rune '-'`,
	}, {
		name: "bad_human_id_too_many_hyphens",
		settings: &dnspb.DeviceSettings{
			LinkedIp: testAddr.AsSlice(),
			DedicatedIps: [][]byte{
				testAddr.AsSlice(),
			},
			Id:           backendtest.DeviceIDStr,
			Name:         testDeviceName,
			HumanIdLower: "aaa---aaa",
		},
		bindSet: backendtest.Bind,
		wantErrMsg: `lowercase human id: bad lowercase human id "aaa---aaa": ` +
			`at index 3: max 2 consecutive hyphens are allowed`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.settings.ToInternal(tc.bindSet)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
