package devicesetter_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicesetter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	srvPlainWithBindData.SetBindData([]*agd.ServerBindData{{
		ListenConfig: &agdtest.ListenConfig{},
		PrefixAddr: &agdnet.PrefixNetAddr{
			// TODO(a.garipov): Move to dnssvctest?
			Prefix: netip.MustParsePrefix("192.0.2.0/30"),
			Net:    "udp",
			Port:   53,
		},
	}})

	testutil.DiscardLogOutput(m)
}

// Common requests for tests.
var (
	reqNormal = dnsservertest.NewReq(dnssvctest.DomainFQDN, dns.TypeA, dns.ClassINET)
	reqEDNS   = dnsservertest.NewReq(
		dnssvctest.DomainFQDN,
		dns.TypeA,
		dns.ClassINET,
		dnsservertest.SectionExtra{
			newExtraOPT(1234, []byte{5, 6, 7, 8}),
		},
	)
	reqEDNSDevID = dnsservertest.NewReq(
		dnssvctest.DomainFQDN,
		dns.TypeA,
		dns.ClassINET,
		dnsservertest.SectionExtra{
			newExtraOPT(devicesetter.DnsmasqCPEIDOption, []byte(dnssvctest.DeviceID)),
		},
	)
	reqEDNSBadDevID = dnsservertest.NewReq(
		dnssvctest.DomainFQDN,
		dns.TypeA,
		dns.ClassINET,
		dnsservertest.SectionExtra{
			newExtraOPT(devicesetter.DnsmasqCPEIDOption, []byte("!!!")),
		},
	)
)

// testPassword is the common password for tests.
//
// TODO(a.garipov): Move to dnssvctest?
const testPassword = "123456"

// newExtraOPT returns a new dns.OPT with a local option with the given code and
// data.
func newExtraOPT(code uint16, data []byte) (opt *dns.OPT) {
	return &dns.OPT{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeOPT,
		},
		Option: []dns.EDNS0{&dns.EDNS0_LOCAL{
			Code: code,
			Data: data,
		}},
	}
}

// Common servers for tests.
var (
	srvPlain = &agd.Server{
		Protocol:        agd.ProtoDNS,
		LinkedIPEnabled: false,
	}
	srvPlainWithLinkedIP = &agd.Server{
		Protocol:        agd.ProtoDNS,
		LinkedIPEnabled: true,
	}
	srvDoH = &agd.Server{
		Protocol: agd.ProtoDoH,
	}
	srvDoQ = &agd.Server{
		Protocol: agd.ProtoDoQ,
	}
	srvDoT = &agd.Server{
		Protocol: agd.ProtoDoT,
	}

	// NOTE:  The bind data are set in [TestMain].
	srvPlainWithBindData = &agd.Server{
		Protocol:        agd.ProtoDNS,
		LinkedIPEnabled: false,
	}
)

// Common addresses for tests.
//
// TODO(a.garipov): Move more common variables and constants to dnssvctest.
var (
	linkedAddr    = netip.MustParseAddr("192.0.2.1")
	dedicatedAddr = netip.MustParseAddr("192.0.2.2")

	linkedAddrPort    = netip.AddrPortFrom(linkedAddr, 12345)
	dedicatedAddrPort = netip.AddrPortFrom(dedicatedAddr, 53)
)

// Common profiles and devices for tests.
var (
	profNormal = &agd.Profile{
		BlockingMode: &dnsmsg.BlockingModeNullIP{},
		ID:           dnssvctest.ProfileID,
		DeviceIDs:    []agd.DeviceID{dnssvctest.DeviceID},
		Deleted:      false,
	}

	profDeleted = &agd.Profile{
		BlockingMode: &dnsmsg.BlockingModeNullIP{},
		ID:           dnssvctest.ProfileID,
		DeviceIDs:    []agd.DeviceID{dnssvctest.DeviceID},
		Deleted:      true,
	}

	devNormal = &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled: false,
		},
		ID:       dnssvctest.DeviceID,
		LinkedIP: linkedAddr,
	}
)

// newDevAuth returns a new device with the given parameters for tests.
func newDevAuth(dohAuthOnly, passwdMatches bool) (d *agd.Device) {
	return &agd.Device{
		Auth: &agd.AuthSettings{
			PasswordHash: &agdtest.Authenticator{
				OnAuthenticate: func(_ context.Context, _ []byte) (ok bool) {
					return passwdMatches
				},
			},
			Enabled:     true,
			DoHAuthOnly: dohAuthOnly,
		},
		ID: dnssvctest.DeviceID,
	}
}

// newOnProfileByDedicatedIP returns a function with the type of
// [agdtest.ProfileDB.OnProfileByDedicatedIP] that returns p and d only when
// localIP is equal to the given one.
func newOnProfileByDedicatedIP(
	wantLocalIP netip.Addr,
) (f func(_ context.Context, localIP netip.Addr) (p *agd.Profile, d *agd.Device, err error)) {
	return func(_ context.Context, localIP netip.Addr) (p *agd.Profile, d *agd.Device, err error) {
		if localIP == wantLocalIP {
			return profNormal, devNormal, nil
		}

		return nil, nil, profiledb.ErrDeviceNotFound
	}
}

// newOnProfileByDeviceID returns a function with the type of
// [agdtest.ProfileDB.OnProfileByDeviceID] that returns p and d only when devID
// is equal to the given one.
func newOnProfileByDeviceID(
	wantDevID agd.DeviceID,
) (f func(_ context.Context, devID agd.DeviceID) (p *agd.Profile, d *agd.Device, err error)) {
	return func(_ context.Context, devID agd.DeviceID) (p *agd.Profile, d *agd.Device, err error) {
		if devID == wantDevID {
			return profNormal, devNormal, nil
		}

		return nil, nil, profiledb.ErrDeviceNotFound
	}
}

// newOnProfileByLinkedIP returns a function with the type of
// [agdtest.ProfileDB.OnProfileByLinkedIP] that returns p and d only when
// remoteIP is equal to the given one.
func newOnProfileByLinkedIP(
	wantRemoteIP netip.Addr,
) (f func(_ context.Context, remoteIP netip.Addr) (p *agd.Profile, d *agd.Device, err error)) {
	return func(_ context.Context, remoteIP netip.Addr) (p *agd.Profile, d *agd.Device, err error) {
		if remoteIP == wantRemoteIP {
			return profNormal, devNormal, nil
		}

		return nil, nil, profiledb.ErrDeviceNotFound
	}
}

func TestDefault_SetDevice_dnscrypt(t *testing.T) {
	t.Parallel()

	df := devicesetter.NewDefault(&devicesetter.Config{
		Server: &agd.Server{
			Protocol: agd.ProtoDNSCrypt,
		},
	})

	ctx := context.Background()
	ri := &agd.RequestInfo{}
	err := df.SetDevice(ctx, reqNormal, ri, dnssvctest.ServerAddrPort)
	assert.Nil(t, err)
	assert.Nil(t, ri.Profile)
	assert.Nil(t, ri.Device)
}
