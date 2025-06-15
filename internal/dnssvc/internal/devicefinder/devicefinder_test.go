package devicefinder_test

import (
	"cmp"
	"context"
	"net/netip"
	"net/url"
	"os"
	"path"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicefinder"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
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

	os.Exit(m.Run())
}

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// Common requests for tests.
var (
	reqNormal = dnsservertest.NewReq(
		dnssvctest.DomainFQDN,
		dns.TypeA,
		dns.ClassINET,
	)
	reqEDNS = dnsservertest.NewReq(
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
			newExtraOPT(devicefinder.DnsmasqCPEIDOption, []byte(dnssvctest.DeviceID)),
		},
	)
	reqEDNSBadDevID = dnsservertest.NewReq(
		dnssvctest.DomainFQDN,
		dns.TypeA,
		dns.ClassINET,
		dnsservertest.SectionExtra{
			newExtraOPT(devicefinder.DnsmasqCPEIDOption, []byte("!!!")),
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

// Common profiles, devices, and results for tests.
var (
	profNormal = &agd.Profile{
		BlockingMode: &dnsmsg.BlockingModeNullIP{},
		ID:           dnssvctest.ProfileID,
		DeviceIDs:    container.NewMapSet(dnssvctest.DeviceID),
		Deleted:      false,
	}

	profDeleted = &agd.Profile{
		BlockingMode: &dnsmsg.BlockingModeNullIP{},
		ID:           dnssvctest.ProfileID,
		DeviceIDs:    container.NewMapSet(dnssvctest.DeviceID),
		Deleted:      true,
	}

	devNormal = &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled: false,
		},
		ID:       dnssvctest.DeviceID,
		LinkedIP: dnssvctest.LinkedAddr,
	}

	devAuto = &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled: false,
		},
		ID:           dnssvctest.DeviceID,
		HumanIDLower: dnssvctest.HumanIDLower,
	}

	resNormal = &agd.DeviceResultOK{
		Device:  devNormal,
		Profile: profNormal,
	}

	resAuto = &agd.DeviceResultOK{
		Device:  devAuto,
		Profile: profNormal,
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

// newOnProfileByHumanID returns a function with the type of
// [agdtest.ProfileDB.OnProfileByHumanID] that returns p and d only when id and
// humanID are equal to the given one.
func newOnProfileByHumanID(
	wantProfID agd.ProfileID,
	wantHumanID agd.HumanIDLower,
) (
	f func(
		_ context.Context,
		id agd.ProfileID,
		humanID agd.HumanIDLower,
	) (p *agd.Profile, d *agd.Device, err error),
) {
	return func(
		_ context.Context,
		id agd.ProfileID,
		humanID agd.HumanIDLower,
	) (p *agd.Profile, d *agd.Device, err error) {
		if id == wantProfID && humanID == wantHumanID {
			return profNormal, devAuto, nil
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

// assertEqualResult is a helper that uses [assert.Equal] for all result types
// except [*agd.DeviceResultError], for which it uses [testutil.AssertErrorMsg].
func assertEqualResult(tb testing.TB, want, got agd.DeviceResult) {
	tb.Helper()

	switch want := want.(type) {
	case *agd.DeviceResultError:
		gotRE := testutil.RequireTypeAssert[*agd.DeviceResultError](tb, got)
		testutil.AssertErrorMsg(tb, want.Err.Error(), gotRE.Err)
	default:
		assert.Equal(tb, want, got)
	}
}

// newDefault is is a helper for creating the device finders for tests.  c may
// be nil, and all zero-value fields in c are replaced with defaults for tests.
// The default server is [srvDoH].
func newDefault(tb testing.TB, c *devicefinder.Config) (f *devicefinder.Default) {
	tb.Helper()

	c = cmp.Or(c, &devicefinder.Config{})

	c.HumanIDParser = cmp.Or(c.HumanIDParser, agd.NewHumanIDParser())
	c.Logger = cmp.Or(c.Logger, testLogger)
	c.Server = cmp.Or(c.Server, srvDoH)
	c.CustomDomainDB = cmp.Or[devicefinder.CustomDomainDB](
		c.CustomDomainDB,
		devicefinder.EmptyCustomDomainDB{},
	)
	c.ProfileDB = cmp.Or[profiledb.Interface](c.ProfileDB, agdtest.NewProfileDB())

	return devicefinder.NewDefault(c)
}

func TestDefault_Find_dnscrypt(t *testing.T) {
	t.Parallel()

	df := newDefault(t, &devicefinder.Config{
		Server: &agd.Server{
			Protocol: agd.ProtoDNSCrypt,
		},
	})

	ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
	r := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
	assert.Nil(t, r)
}

func BenchmarkDefault(b *testing.B) {
	profDB := &agdtest.ProfileDB{
		OnCreateAutoDevice: func(
			_ context.Context,
			_ agd.ProfileID,
			_ agd.HumanID,
			_ agd.DeviceType,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},

		OnProfileByDedicatedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			return profNormal, devNormal, nil
		},

		OnProfileByDeviceID: func(
			_ context.Context,
			_ agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			return profNormal, devNormal, nil
		},

		OnProfileByHumanID: func(
			_ context.Context,
			_ agd.ProfileID,
			_ agd.HumanIDLower,
		) (p *agd.Profile, d *agd.Device, err error) {
			return profNormal, devNormal, nil
		},

		OnProfileByLinkedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			return profNormal, devNormal, nil
		},
	}

	benchCases := []struct {
		conf       *devicefinder.Config
		req        *dns.Msg
		srvReqInfo *dnsserver.RequestInfo
		name       string
	}{{
		conf: &devicefinder.Config{
			Server:        srvDoT,
			ProfileDB:     profDB,
			DeviceDomains: []string{dnssvctest.DomainForDevices},
		},
		req: reqNormal,
		srvReqInfo: &dnsserver.RequestInfo{
			TLSServerName: dnssvctest.DeviceIDSrvName,
		},
		name: "dot",
	}, {
		conf: &devicefinder.Config{
			ProfileDB:     profDB,
			DeviceDomains: []string{dnssvctest.DomainForDevices},
		},
		req: reqNormal,
		srvReqInfo: &dnsserver.RequestInfo{
			TLSServerName: dnssvctest.DeviceIDSrvName,
			URL: &url.URL{
				Path: dnsserver.PathDoH,
			},
		},
		name: "doh_domain",
	}, {
		conf: &devicefinder.Config{
			ProfileDB:     profDB,
			DeviceDomains: []string{dnssvctest.DomainForDevices},
		},
		req: reqNormal,
		srvReqInfo: &dnsserver.RequestInfo{
			TLSServerName: dnssvctest.DomainForDevices,
			URL: &url.URL{
				Path: path.Join(dnsserver.PathDoH, dnssvctest.DeviceIDStr),
			},
		},
		name: "doh_path",
	}, {
		conf: &devicefinder.Config{
			Server:        srvPlain,
			ProfileDB:     profDB,
			DeviceDomains: nil,
		},
		req:        reqEDNSDevID,
		srvReqInfo: &dnsserver.RequestInfo{},
		name:       "dns_edns",
	}, {
		conf: &devicefinder.Config{
			Server:        srvPlainWithBindData,
			ProfileDB:     profDB,
			DeviceDomains: nil,
		},
		req:        reqNormal,
		srvReqInfo: &dnsserver.RequestInfo{},
		name:       "dns_laddr",
	}, {
		conf: &devicefinder.Config{
			Server:        srvPlainWithLinkedIP,
			ProfileDB:     profDB,
			DeviceDomains: nil,
		},
		req:        reqNormal,
		srvReqInfo: &dnsserver.RequestInfo{},
		name:       "dns_raddr",
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			df := newDefault(b, bc.conf)

			ctx := testutil.ContextWithTimeout(b, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, bc.srvReqInfo)

			var devRes agd.DeviceResult

			b.ReportAllocs()
			for b.Loop() {
				devRes = df.Find(
					ctx,
					bc.req,
					dnssvctest.ClientAddrPort,
					dnssvctest.ServerAddrPort,
				)
			}

			_ = testutil.RequireTypeAssert[*agd.DeviceResultOK](b, devRes)
		})
	}

	// Most recent results:
	//
	// goos: linux
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicefinder
	// cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	// BenchmarkDefault/dot-16         	 2654976	       406.5 ns/op	      32 B/op	       2 allocs/op
	// BenchmarkDefault/doh_domain-16  	 1560818	       758.5 ns/op	      80 B/op	       4 allocs/op
	// BenchmarkDefault/doh_path-16    	 1922390	       639.2 ns/op	      96 B/op	       4 allocs/op
	// BenchmarkDefault/dns_edns-16    	 3430594	       396.1 ns/op	      40 B/op	       3 allocs/op
	// BenchmarkDefault/dns_laddr-16   	 6179818	       206.0 ns/op	      16 B/op	       1 allocs/op
	// BenchmarkDefault/dns_raddr-16   	 6360699	       184.4 ns/op	      16 B/op	       1 allocs/op
}
