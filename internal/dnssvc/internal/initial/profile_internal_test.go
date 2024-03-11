package initial

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

// Bind data for tests.
var (
	bindDataAddr = &agd.ServerBindData{
		AddrPort: netip.MustParseAddrPort("1.2.3.4:53"),
	}

	bindDataIface = &agd.ServerBindData{
		ListenConfig: &agdtest.ListenConfig{},
		PrefixAddr: &agdnet.PrefixNetAddr{
			Prefix: netip.MustParsePrefix("1.2.3.0/24"),
			Net:    "",
			Port:   53,
		},
	}

	bindDataIfaceSingleIP = &agd.ServerBindData{
		ListenConfig: &agdtest.ListenConfig{},
		PrefixAddr: &agdnet.PrefixNetAddr{
			Prefix: netip.PrefixFrom(dnssvctest.ServerAddr, 32),
			Net:    "",
			Port:   dnssvctest.ServerAddrPort.Port(),
		},
	}
)

func TestMiddleware_profile(t *testing.T) {
	prof := &agd.Profile{
		Access: access.EmptyProfile{},
		ID:     dnssvctest.ProfileID,
		DeviceIDs: []agd.DeviceID{
			dnssvctest.DeviceID,
		},
	}

	dev := &agd.Device{
		ID:       dnssvctest.DeviceID,
		LinkedIP: dnssvctest.ClientAddr,
		DedicatedIPs: []netip.Addr{
			dnssvctest.ServerAddr,
		},
	}

	testCases := []struct {
		wantDev         *agd.Device
		wantProf        *agd.Profile
		wantByWhat      string
		wantErrMsg      string
		name            string
		id              agd.DeviceID
		proto           agd.Protocol
		linkedIPEnabled bool
	}{{
		wantDev:         nil,
		wantProf:        nil,
		wantByWhat:      "",
		wantErrMsg:      "device not found",
		name:            "no_device_id",
		id:              "",
		proto:           agd.ProtoDNS,
		linkedIPEnabled: true,
	}, {
		wantDev:         dev,
		wantProf:        prof,
		wantByWhat:      byDeviceID,
		wantErrMsg:      "",
		name:            "device_id",
		id:              dnssvctest.DeviceID,
		proto:           agd.ProtoDNS,
		linkedIPEnabled: true,
	}, {
		wantDev:         nil,
		wantProf:        nil,
		wantByWhat:      "",
		wantErrMsg:      "device not found",
		name:            "linked_ip_dot",
		id:              "",
		proto:           agd.ProtoDoT,
		linkedIPEnabled: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := dnssvctest.NewServer("test_server", tc.proto, bindDataAddr)
			srv.LinkedIPEnabled = tc.linkedIPEnabled

			mw := New(&Config{
				Server:           srv,
				ProfileDB:        newProfileDB(t, prof, dev, tc.wantByWhat),
				ProfileDBEnabled: true,
			})

			ctx := context.Background()
			gotProf, gotDev, gotByWhat, err := mw.profile(
				ctx,
				dnssvctest.ServerAddrPort,
				dnssvctest.ClientAddr,
				tc.id,
			)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantProf, gotProf)
			assert.Equal(t, tc.wantDev, gotDev)
			assert.Equal(t, tc.wantByWhat, gotByWhat)
		})
	}
}

func TestMiddleware_profileByAddrs(t *testing.T) {
	prof := &agd.Profile{
		Access: access.EmptyProfile{},
		ID:     dnssvctest.ProfileID,
		DeviceIDs: []agd.DeviceID{
			dnssvctest.DeviceID,
		},
	}

	dev := &agd.Device{
		ID:       dnssvctest.DeviceID,
		LinkedIP: dnssvctest.ClientAddr,
		DedicatedIPs: []netip.Addr{
			dnssvctest.ServerAddr,
		},
	}

	testCases := []struct {
		wantDev         *agd.Device
		wantProf        *agd.Profile
		wantByWhat      string
		wantErrMsg      string
		name            string
		bindData        []*agd.ServerBindData
		linkedIPEnabled bool
	}{{
		wantDev:         dev,
		wantProf:        prof,
		wantByWhat:      byLinkedIP,
		wantErrMsg:      "",
		name:            "linked_ip",
		bindData:        []*agd.ServerBindData{bindDataAddr},
		linkedIPEnabled: true,
	}, {
		wantDev:         nil,
		wantProf:        nil,
		wantByWhat:      "",
		wantErrMsg:      "device not found",
		name:            "linked_ip_disabled",
		bindData:        []*agd.ServerBindData{bindDataAddr},
		linkedIPEnabled: false,
	}, {
		wantDev:         dev,
		wantProf:        prof,
		wantByWhat:      byDedicatedIP,
		wantErrMsg:      "",
		name:            "dedicated_ip",
		bindData:        []*agd.ServerBindData{bindDataIface},
		linkedIPEnabled: true,
	}, {
		wantDev:         nil,
		wantProf:        nil,
		wantByWhat:      "",
		wantErrMsg:      "drop",
		name:            "dedicated_ip_not_found",
		bindData:        []*agd.ServerBindData{bindDataIface},
		linkedIPEnabled: true,
	}, {
		wantDev:    nil,
		wantProf:   nil,
		wantByWhat: "",
		wantErrMsg: "device not found",
		name:       "dedicated_ip_and_single_ip",
		bindData: []*agd.ServerBindData{
			bindDataIface,
			bindDataIfaceSingleIP,
		},
		linkedIPEnabled: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := dnssvctest.NewServer("test_server", agd.ProtoDNS, tc.bindData...)
			srv.LinkedIPEnabled = tc.linkedIPEnabled

			mw := New(&Config{
				Server:           srv,
				ProfileDB:        newProfileDB(t, prof, dev, tc.wantByWhat),
				ProfileDBEnabled: true,
			})

			ctx := context.Background()
			gotProf, gotDev, gotByWhat, err := mw.profileByAddrs(
				ctx,
				dnssvctest.ServerAddrPort,
				dnssvctest.ClientAddr,
			)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantProf, gotProf)
			assert.Equal(t, tc.wantDev, gotDev)
			assert.Equal(t, tc.wantByWhat, gotByWhat)
		})
	}
}

// newProfileDB is a helper that creates a database returning prof and dev
// depending on which parameter should be used to find them.
func newProfileDB(
	t *testing.T,
	prof *agd.Profile,
	dev *agd.Device,
	byWhat string,
) (db profiledb.Interface) {
	return &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			gotID agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			assert.Equal(t, dnssvctest.DeviceID, gotID)

			if byWhat == byDeviceID {
				return prof, dev, nil
			}

			return nil, nil, profiledb.ErrDeviceNotFound
		},
		OnProfileByDedicatedIP: func(
			_ context.Context,
			gotLocalIP netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			assert.Equal(t, dnssvctest.ServerAddr, gotLocalIP)

			if byWhat == byDedicatedIP {
				return prof, dev, nil
			}

			return nil, nil, profiledb.ErrDeviceNotFound
		},
		OnProfileByLinkedIP: func(
			_ context.Context,
			gotRemoteIP netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			assert.Equal(t, dnssvctest.ClientAddr, gotRemoteIP)

			if byWhat == byLinkedIP {
				return prof, dev, nil
			}

			return nil, nil, profiledb.ErrDeviceNotFound
		},
	}
}
