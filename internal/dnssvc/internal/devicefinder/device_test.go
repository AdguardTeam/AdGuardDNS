package devicefinder_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicefinder"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault_Find_plainAddrs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		req     *dns.Msg
		srv     *agd.Server
		wantRes agd.DeviceResult
		laddr   netip.AddrPort
		raddr   netip.AddrPort
		name    string
	}{{
		req:     reqNormal,
		srv:     srvPlainWithLinkedIP,
		wantRes: nil,
		laddr:   dnssvctest.ServerAddrPort,
		raddr:   dnssvctest.ClientAddrPort,
		name:    "no_match",
	}, {
		req:     reqNormal,
		srv:     srvPlainWithLinkedIP,
		wantRes: resNormal,
		laddr:   dnssvctest.ServerAddrPort,
		raddr:   dnssvctest.LinkedAddrPort,
		name:    "linked_ip",
	}, {
		req:     reqNormal,
		srv:     srvPlain,
		wantRes: nil,
		laddr:   dnssvctest.ServerAddrPort,
		raddr:   dnssvctest.LinkedAddrPort,
		name:    "linked_ip_not_supported",
	}, {
		req:     reqNormal,
		srv:     srvPlainWithBindData,
		wantRes: resNormal,
		laddr:   dnssvctest.DedicatedAddrPort,
		raddr:   dnssvctest.ClientAddrPort,
		name:    "dedicated",
	}, {
		req: reqNormal,
		srv: srvPlainWithBindData,
		wantRes: &agd.DeviceResultUnknownDedicated{
			Err: profiledb.ErrDeviceNotFound,
		},
		laddr: dnssvctest.ServerAddrPort,
		raddr: dnssvctest.ClientAddrPort,
		name:  "dedicated_not_found",
	}, {
		req:     reqNormal,
		srv:     srvPlain,
		wantRes: nil,
		laddr:   dnssvctest.DedicatedAddrPort,
		raddr:   dnssvctest.ClientAddrPort,
		name:    "dedicated_not_supported",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profDB := agdtest.NewProfileDB()
			profDB.OnProfileByDedicatedIP = newOnProfileByDedicatedIP(dnssvctest.DedicatedAddr)
			profDB.OnProfileByLinkedIP = newOnProfileByLinkedIP(dnssvctest.LinkedAddr)

			df := devicefinder.NewDefault(&devicefinder.Config{
				Logger:        slogutil.NewDiscardLogger(),
				ProfileDB:     profDB,
				HumanIDParser: agd.NewHumanIDParser(),
				Server:        tc.srv,
				DeviceDomains: nil,
			})

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{})
			got := df.Find(ctx, tc.req, tc.raddr, tc.laddr)
			assertEqualResult(t, tc.wantRes, got)
		})
	}
}

func TestDefault_Find_plainEDNS(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		req        *dns.Msg
		srv        *agd.Server
		wantRes    agd.DeviceResult
		wantProf   *agd.Profile
		wantDev    *agd.Device
		wantErrMsg string
		laddr      netip.AddrPort
		raddr      netip.AddrPort
		name       string
	}{{
		req:     reqNormal,
		srv:     srvPlain,
		wantRes: nil,
		laddr:   dnssvctest.ServerAddrPort,
		raddr:   dnssvctest.ClientAddrPort,
		name:    "no_edns",
	}, {
		req:     reqEDNS,
		srv:     srvPlain,
		wantRes: nil,
		laddr:   dnssvctest.ServerAddrPort,
		raddr:   dnssvctest.ClientAddrPort,
		name:    "edns_no_dev_id",
	}, {
		req:     reqEDNSDevID,
		srv:     srvPlain,
		wantRes: resNormal,
		laddr:   dnssvctest.ServerAddrPort,
		raddr:   dnssvctest.ClientAddrPort,
		name:    "edns_dev_id",
	}, {
		req: reqEDNSBadDevID,
		srv: srvPlain,
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`edns option device id check: bad device id "!!!": bad hostname label rune '!'`,
			),
		},
		laddr: dnssvctest.ServerAddrPort,
		raddr: dnssvctest.ClientAddrPort,
		name:  "edns_bad_dev_id",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profDB := agdtest.NewProfileDB()
			profDB.OnProfileByDeviceID = newOnProfileByDeviceID(dnssvctest.DeviceID)

			df := devicefinder.NewDefault(&devicefinder.Config{
				Logger:        slogutil.NewDiscardLogger(),
				ProfileDB:     profDB,
				HumanIDParser: agd.NewHumanIDParser(),
				Server:        tc.srv,
				DeviceDomains: nil,
			})

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{})
			got := df.Find(ctx, tc.req, tc.raddr, tc.laddr)
			assertEqualResult(t, tc.wantRes, got)
		})
	}
}

func TestDefault_Find_deleted(t *testing.T) {
	t.Parallel()

	profDB := agdtest.NewProfileDB()
	profDB.OnProfileByLinkedIP = func(
		_ context.Context,
		_ netip.Addr,
	) (p *agd.Profile, d *agd.Device, err error) {
		return profDeleted, devNormal, nil
	}

	df := devicefinder.NewDefault(&devicefinder.Config{
		Logger:        slogutil.NewDiscardLogger(),
		ProfileDB:     profDB,
		HumanIDParser: agd.NewHumanIDParser(),
		Server:        srvPlainWithLinkedIP,
	})

	ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{})
	r := df.Find(ctx, reqNormal, dnssvctest.LinkedAddrPort, dnssvctest.ServerAddrPort)
	assert.Nil(t, r)
}

func TestDefault_Find_byHumanID(t *testing.T) {
	t.Parallel()

	// Use uppercase versions to make sure that the device finder recognizes the
	// device-type and profile data regardless of the case.
	extIDStr := "OTR-" + strings.ToUpper(dnssvctest.ProfileIDStr) + "-" + dnssvctest.HumanIDStr + "-!!!"

	profDB := agdtest.NewProfileDB()
	profDB.OnCreateAutoDevice = func(
		ctx context.Context,
		id agd.ProfileID,
		humanID agd.HumanID,
		devType agd.DeviceType,
	) (p *agd.Profile, d *agd.Device, err error) {
		return profNormal, devAuto, nil
	}
	profDB.OnProfileByHumanID = func(
		_ context.Context,
		_ agd.ProfileID,
		_ agd.HumanIDLower,
	) (p *agd.Profile, d *agd.Device, err error) {
		return nil, nil, profiledb.ErrDeviceNotFound
	}

	df := devicefinder.NewDefault(&devicefinder.Config{
		Logger:        slogutil.NewDiscardLogger(),
		ProfileDB:     profDB,
		HumanIDParser: agd.NewHumanIDParser(),
		Server:        srvDoT,
		DeviceDomains: []string{dnssvctest.DomainForDevices},
	})

	ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
		TLSServerName: extIDStr + "." + dnssvctest.DomainForDevices,
	})

	want := &agd.DeviceResultOK{
		Device:  devAuto,
		Profile: profNormal,
	}
	got := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
	require.Equal(t, want, got)
}
