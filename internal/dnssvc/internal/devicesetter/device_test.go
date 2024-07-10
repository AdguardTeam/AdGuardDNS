package devicesetter_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicesetter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault_SetDevice_plainAddrs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		req        *dns.Msg
		srv        *agd.Server
		wantProf   *agd.Profile
		wantDev    *agd.Device
		wantErrMsg string
		laddr      netip.AddrPort
		raddr      netip.AddrPort
		name       string
	}{{
		req:        reqNormal,
		srv:        srvPlainWithLinkedIP,
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "",
		laddr:      dnssvctest.ServerAddrPort,
		raddr:      dnssvctest.ClientAddrPort,
		name:       "no_match",
	}, {
		req:        reqNormal,
		srv:        srvPlainWithLinkedIP,
		wantProf:   profNormal,
		wantDev:    devNormal,
		wantErrMsg: "",
		laddr:      dnssvctest.ServerAddrPort,
		raddr:      dnssvctest.LinkedAddrPort,
		name:       "linked_ip",
	}, {
		req:        reqNormal,
		srv:        srvPlain,
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "",
		laddr:      dnssvctest.ServerAddrPort,
		raddr:      dnssvctest.LinkedAddrPort,
		name:       "linked_ip_not_supported",
	}, {
		req:        reqNormal,
		srv:        srvPlainWithBindData,
		wantProf:   profNormal,
		wantDev:    devNormal,
		wantErrMsg: "",
		laddr:      dnssvctest.DedicatedAddrPort,
		raddr:      dnssvctest.ClientAddrPort,
		name:       "dedicated",
	}, {
		req:        reqNormal,
		srv:        srvPlainWithBindData,
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "setting profile: unknown dedicated ip",
		laddr:      dnssvctest.ServerAddrPort,
		raddr:      dnssvctest.ClientAddrPort,
		name:       "dedicated_not_found",
	}, {
		req:        reqNormal,
		srv:        srvPlain,
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "",
		laddr:      dnssvctest.DedicatedAddrPort,
		raddr:      dnssvctest.ClientAddrPort,
		name:       "dedicated_not_supported",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profDB := &agdtest.ProfileDB{
				OnCreateAutoDevice: func(
					ctx context.Context,
					id agd.ProfileID,
					humanID agd.HumanID,
					devType agd.DeviceType,
				) (p *agd.Profile, d *agd.Device, err error) {
					panic("not implemented")
				},

				OnProfileByDedicatedIP: newOnProfileByDedicatedIP(dnssvctest.DedicatedAddr),

				OnProfileByDeviceID: func(
					_ context.Context,
					_ agd.DeviceID,
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

				OnProfileByLinkedIP: newOnProfileByLinkedIP(dnssvctest.LinkedAddr),
			}

			pf := devicesetter.NewDefault(&devicesetter.Config{
				ProfileDB:         profDB,
				HumanIDParser:     agd.NewHumanIDParser(),
				Server:            tc.srv,
				DeviceIDWildcards: nil,
			})

			ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{})
			ri := &agd.RequestInfo{
				RemoteIP: tc.raddr.Addr(),
			}

			err := pf.SetDevice(ctx, tc.req, ri, tc.laddr)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantProf, ri.Profile)
			assert.Equal(t, tc.wantDev, ri.Device)
		})
	}
}

func TestDefault_SetDevice_plainEDNS(t *testing.T) {
	testCases := []struct {
		req        *dns.Msg
		srv        *agd.Server
		wantProf   *agd.Profile
		wantDev    *agd.Device
		wantErrMsg string
		laddr      netip.AddrPort
		raddr      netip.AddrPort
		name       string
	}{{
		req:        reqNormal,
		srv:        srvPlain,
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "",
		laddr:      dnssvctest.ServerAddrPort,
		raddr:      dnssvctest.ClientAddrPort,
		name:       "no_edns",
	}, {
		req:        reqEDNS,
		srv:        srvPlain,
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "",
		laddr:      dnssvctest.ServerAddrPort,
		raddr:      dnssvctest.ClientAddrPort,
		name:       "edns_no_dev_id",
	}, {
		req:        reqEDNSDevID,
		srv:        srvPlain,
		wantProf:   profNormal,
		wantDev:    devNormal,
		wantErrMsg: "",
		laddr:      dnssvctest.ServerAddrPort,
		raddr:      dnssvctest.ClientAddrPort,
		name:       "edns_dev_id",
	}, {
		req:        reqEDNSBadDevID,
		srv:        srvPlain,
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: `edns option device id check: bad device id "!!!": bad hostname label rune '!'`,
		laddr:      dnssvctest.ServerAddrPort,
		raddr:      dnssvctest.ClientAddrPort,
		name:       "edns_bad_dev_id",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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

				OnProfileByDeviceID: newOnProfileByDeviceID(dnssvctest.DeviceID),

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

			pf := devicesetter.NewDefault(&devicesetter.Config{
				ProfileDB:         profDB,
				HumanIDParser:     agd.NewHumanIDParser(),
				Server:            tc.srv,
				DeviceIDWildcards: nil,
			})

			ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{})
			ri := &agd.RequestInfo{
				RemoteIP: tc.raddr.Addr(),
			}

			err := pf.SetDevice(ctx, tc.req, ri, tc.laddr)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantProf, ri.Profile)
			assert.Equal(t, tc.wantDev, ri.Device)
		})
	}
}

func TestDefault_SetDevice_deleted(t *testing.T) {
	t.Parallel()

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
			_ agd.DeviceID,
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
			return profDeleted, devNormal, nil
		},
	}

	pf := devicesetter.NewDefault(&devicesetter.Config{
		ProfileDB:     profDB,
		HumanIDParser: agd.NewHumanIDParser(),
		Server:        srvPlainWithLinkedIP,
	})

	raddr := dnssvctest.LinkedAddrPort
	msgCons := agdtest.NewConstructor()
	ri := &agd.RequestInfo{
		Messages: msgCons,
		RemoteIP: raddr.Addr(),
	}

	ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{})
	err := pf.SetDevice(ctx, reqNormal, ri, dnssvctest.ServerAddrPort)
	require.Nil(t, err)

	assert.Nil(t, ri.Profile)
	assert.Nil(t, ri.Device)
	assert.Same(t, msgCons, ri.Messages)
}

func TestDefault_SetDevice_byHumanID(t *testing.T) {
	t.Parallel()

	// Use uppercase versions to make sure that the device setter recognizes the
	// device-type and profile data regardless of the case.
	extIDStr := "OTR-" + strings.ToUpper(dnssvctest.ProfileIDStr) + "-" + dnssvctest.HumanIDStr + "-!!!"

	profDB := &agdtest.ProfileDB{
		OnCreateAutoDevice: func(
			ctx context.Context,
			id agd.ProfileID,
			humanID agd.HumanID,
			devType agd.DeviceType,
		) (p *agd.Profile, d *agd.Device, err error) {
			return profNormal, devAuto, nil
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
			return nil, nil, profiledb.ErrDeviceNotFound
		},

		OnProfileByLinkedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
	}

	df := devicesetter.NewDefault(&devicesetter.Config{
		ProfileDB:         profDB,
		HumanIDParser:     agd.NewHumanIDParser(),
		Server:            srvDoT,
		DeviceIDWildcards: []string{dnssvctest.DomainForDevices},
	})

	ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{
		TLSServerName: extIDStr + "." + dnssvctest.DomainForDevices,
	})
	ri := &agd.RequestInfo{
		RemoteIP: dnssvctest.ClientAddr,
	}

	err := df.SetDevice(ctx, reqNormal, ri, dnssvctest.ServerAddrPort)
	require.NoError(t, err)

	assert.Equal(t, profNormal, ri.Profile)
	assert.Equal(t, devAuto, ri.Device)
}
