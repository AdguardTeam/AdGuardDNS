package initial

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware_profile(t *testing.T) {
	prof := &agd.Profile{
		ID: dnssvctest.ProfileID,
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
		wantDev:         dev,
		wantProf:        prof,
		wantByWhat:      byLinkedIP,
		wantErrMsg:      "",
		name:            "linked_ip",
		id:              "",
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
	}, {
		wantDev:         nil,
		wantProf:        nil,
		wantByWhat:      "",
		wantErrMsg:      "device not found",
		name:            "linked_ip_disabled",
		id:              "",
		proto:           agd.ProtoDoT,
		linkedIPEnabled: false,
	}, {
		wantDev:         dev,
		wantProf:        prof,
		wantByWhat:      byDedicatedIP,
		wantErrMsg:      "",
		name:            "dedicated_ip",
		id:              "",
		proto:           agd.ProtoDNS,
		linkedIPEnabled: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mw := New(&Config{
				Server: &agd.Server{
					Protocol:        tc.proto,
					LinkedIPEnabled: tc.linkedIPEnabled,
				},
				ProfileDB: newProfileDB(t, prof, dev, tc.wantByWhat),
			})

			ctx := context.Background()
			gotProf, gotDev, gotByWhat, err := mw.profile(
				ctx,
				dnssvctest.ServerAddr,
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
