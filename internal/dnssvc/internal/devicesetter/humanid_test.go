package devicesetter_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicesetter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestDefault_SetDevice_humanID(t *testing.T) {
	testCases := []struct {
		name       string
		in         string
		wantErrMsg string
	}{{
		name: "bad_type",
		in:   "!!!-abcd1234-My-Device-X--10",
		wantErrMsg: `tls server name device id check: parsing "!!!-abcd1234-My-Device-X--10": ` +
			`bad device type "!!!": unknown device type`,
	}, {
		name: "bad_profile_id",
		in:   "otr-\x00-My-Device-X--10",
		wantErrMsg: `tls server name device id check: parsing "otr-\x00-My-Device-X--10": ` +
			`bad profile id: bad char '\x00' at index 0`,
	}, {
		name: "bad_human_id",
		in:   "otr-abcd1234-!!!",
		wantErrMsg: `tls server name device id check: parsing "otr-abcd1234-!!!": ` +
			`bad non-normalized human id "!!!": cannot normalize`,
	}}

	profDB := &agdtest.ProfileDB{
		OnCreateAutoDevice: func(
			ctx context.Context,
			id agd.ProfileID,
			humanID agd.HumanID,
			devType agd.DeviceType,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},

		OnProfileByDedicatedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},

		OnProfileByDeviceID: func(
			_ context.Context,
			devID agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},

		OnProfileByHumanID: func(
			_ context.Context,
			_ agd.ProfileID,
			_ agd.HumanIDLower,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},

		OnProfileByLinkedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			df := devicesetter.NewDefault(&devicesetter.Config{
				ProfileDB:         profDB,
				HumanIDParser:     agd.NewHumanIDParser(),
				Server:            srvDoT,
				DeviceIDWildcards: []string{dnssvctest.DomainForDevices},
			})

			ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{
				TLSServerName: tc.in + "." + dnssvctest.DomainForDevices,
			})
			ri := &agd.RequestInfo{
				RemoteIP: dnssvctest.ClientAddr,
			}

			err := df.SetDevice(ctx, reqNormal, ri, dnssvctest.ServerAddrPort)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
