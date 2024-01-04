package ecscache_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/ecscache"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common test domain names.
const (
	reqHostname = "example.com."
	reqCNAME    = "cname.example.com."
	reqNS1      = "ns1.example.com."
	reqNS2      = "ns2.example.com."
)

// defaultTTL is the default TTL to use in tests.
const defaultTTL uint32 = 3600

// remoteIP is the IP to use for tests.
var remoteIP = netip.MustParseAddr("1.2.3.4")

func TestMiddleware_Wrap_noECS(t *testing.T) {
	aReq := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
	cnameReq := dnsservertest.NewReq(reqHostname, dns.TypeCNAME, dns.ClassINET)
	cnameAns := dnsservertest.SectionAnswer{
		dnsservertest.NewCNAME(reqHostname, defaultTTL, reqCNAME),
	}
	soaNS := dnsservertest.SectionNs{
		dnsservertest.NewSOA(reqHostname, defaultTTL, reqNS1, reqNS2),
	}

	knownIP := netip.MustParseAddr("1.2.3.4")
	testTTL := 60 * time.Second

	const N = 5
	testCases := []struct {
		req        *dns.Msg
		resp       *dns.Msg
		minTTL     *time.Duration
		name       string
		wantNumReq int
		wantTTL    uint32
	}{{
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, defaultTTL, knownIP),
		}),
		name:       "simple_a",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
		minTTL:     nil,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq),
		name:       "empty_answer",
		wantNumReq: N,
		wantTTL:    0,
		minTTL:     nil,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, soaNS),
		name:       "authoritative_nodata",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
		minTTL:     nil,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, cnameAns, soaNS),
		name:       "nodata_with_cname",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
		minTTL:     nil,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, cnameAns),
		name:       "nodata_with_cname_no_soa",
		wantNumReq: N,
		wantTTL:    defaultTTL,
		minTTL:     nil,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeNameError, aReq, dnsservertest.SectionNs{
			dnsservertest.NewNS(reqHostname, defaultTTL, reqNS1),
		}),
		name: "non_authoritative_nxdomain",
		// TODO(ameshkov): Consider https://datatracker.ietf.org/doc/html/rfc2308#section-3.
		wantNumReq: 1,
		wantTTL:    0,
		minTTL:     nil,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeNameError, aReq, soaNS),
		name:       "authoritative_nxdomain",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
		minTTL:     nil,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeServerFailure, aReq),
		name:       "simple_server_failure",
		wantNumReq: 1,
		wantTTL:    dnsmsg.ServFailMaxCacheTTL,
		minTTL:     nil,
	}, {
		req: cnameReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, cnameReq, dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(reqHostname, defaultTTL, reqCNAME),
		}),
		name:       "simple_cname_ans",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
		minTTL:     nil,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 0, knownIP),
		}),
		name:       "expired_one",
		wantNumReq: N,
		wantTTL:    0,
		minTTL:     nil,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 10, knownIP),
		}),
		name:       "override_ttl_ok",
		wantNumReq: 1,
		minTTL:     &testTTL,
		wantTTL:    uint32(testTTL.Seconds()),
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 1000, knownIP),
		}),
		name:       "override_ttl_max",
		wantNumReq: 1,
		minTTL:     &testTTL,
		wantTTL:    1000,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 0, knownIP),
		}),
		name:       "override_ttl_zero",
		wantNumReq: N,
		minTTL:     &testTTL,
		wantTTL:    0,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeServerFailure, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, dnsmsg.ServFailMaxCacheTTL, knownIP),
		}),
		name:       "override_ttl_servfail",
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    dnsmsg.ServFailMaxCacheTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeNotImplemented, aReq, soaNS),
		name:       "unexpected_response",
		wantNumReq: N,
		wantTTL:    0,
		minTTL:     nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			numReq := 0
			handler := dnsserver.HandlerFunc(
				func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
					numReq++

					return rw.WriteMsg(ctx, req, tc.resp)
				},
			)

			var minTTL time.Duration
			if tc.minTTL != nil {
				minTTL = *tc.minTTL
			}

			withCache := newWithCache(
				t,
				handler,
				geoip.CountryNone,
				netutil.ZeroPrefix(netutil.AddrFamilyIPv4),
				minTTL,
				tc.minTTL != nil,
			)
			ri := &agd.RequestInfo{
				Host:     tc.req.Question[0].Name,
				RemoteIP: remoteIP,
			}

			var msg *dns.Msg
			for i := 0; i < N; i++ {
				msg = exchange(t, ri, withCache, tc.req)
			}

			assert.Equal(t, tc.resp, msg)
			assert.Equal(t, tc.wantNumReq, numReq)

			if len(msg.Answer) > 0 {
				assert.Equal(t, tc.wantTTL, msg.Answer[0].Header().Ttl)
			}
		})
	}
}

const prefixLen = 24

// newAReq returns new test A request with ECS option.
func newAReq(hostname string, ip net.IP) (req *dns.Msg) {
	aReqNoECS := dnsservertest.NewReq(hostname, dns.TypeA, dns.ClassINET)
	aReqNoECS.SetEdns0(dnsmsg.DefaultEDNSUDPSize, false)

	req = aReqNoECS.Copy()
	opt := req.Extra[len(req.Extra)-1].(*dns.OPT)

	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        uint16(netutil.AddrFamilyIPv4),
		SourceNetmask: prefixLen,
		SourceScope:   0,
		Address:       ip,
	})

	return req
}

func TestMiddleware_Wrap_ecs(t *testing.T) {
	aReqNoECS := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)

	ip := net.IP{1, 2, 3, 0}
	aReq := newAReq(reqHostname, ip)
	fakeECSReq := newAReq(maps.Keys(ecscache.FakeECSFQDNs)[0], ip)

	subnet := netip.PrefixFrom(netip.AddrFrom4([4]byte(ip)), prefixLen)
	const ctry = geoip.CountryAD

	defaultCtrySubnet := netip.MustParsePrefix("1.2.0.0/16")
	ecsExtra := dnsservertest.NewECSExtra(
		net.IP{1, 2, 0, 0},
		uint16(netutil.AddrFamilyIPv4),
		20,
		20,
	)

	testCases := []struct {
		req        *dns.Msg
		respECS    dns.RR
		wantECS    *agd.ECS
		ctrySubnet netip.Prefix
		name       string
	}{{
		req:     aReq,
		respECS: ecsExtra,
		wantECS: &agd.ECS{
			Location: &geoip.Location{
				Country: ctry,
			},
			Subnet: subnet,
			Scope:  0,
		},
		ctrySubnet: defaultCtrySubnet,
		name:       "with_country",
	}, {
		req:     aReq,
		respECS: ecsExtra,
		wantECS: &agd.ECS{
			Location: &geoip.Location{
				Country: ctry,
			},
			Subnet: subnet,
			Scope:  0,
		},
		ctrySubnet: netutil.ZeroPrefix(netutil.AddrFamilyIPv4),
		name:       "no_country",
	}, {
		req:        aReqNoECS,
		respECS:    ecsExtra,
		wantECS:    nil,
		ctrySubnet: defaultCtrySubnet,
		name:       "edns_no_ecs",
	}, {
		req:        aReq,
		respECS:    ecsExtra,
		wantECS:    nil,
		ctrySubnet: defaultCtrySubnet,
		name:       "country_from_ip",
	}, {
		req: aReq,
		respECS: dnsservertest.NewECSExtra(
			netutil.IPv4Zero(),
			uint16(netutil.AddrFamilyIPv4),
			0,
			0,
		),
		wantECS: &agd.ECS{
			Location: &geoip.Location{
				Country: geoip.CountryNone,
			},
			Subnet: netutil.ZeroPrefix(netutil.AddrFamilyIPv4),
			Scope:  0,
		},
		ctrySubnet: defaultCtrySubnet,
		name:       "zero_ecs",
	}, {
		req:     fakeECSReq,
		respECS: ecsExtra,
		wantECS: &agd.ECS{
			Location: &geoip.Location{
				Country: ctry,
			},
			Subnet: netutil.ZeroPrefix(netutil.AddrFamilyIPv4),
			Scope:  0,
		},
		ctrySubnet: defaultCtrySubnet,
		name:       "fake_ecs_domain",
	}}

	const N = 5

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := dnsservertest.NewResp(
				dns.RcodeSuccess,
				aReq,
				dnsservertest.SectionAnswer{dnsservertest.NewA(
					reqHostname,
					defaultTTL,
					netip.MustParseAddr("1.2.3.4"),
				)},
				dnsservertest.SectionExtra{tc.respECS},
			)

			numReq := 0
			handler := dnsserver.HandlerFunc(
				func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
					numReq++

					return rw.WriteMsg(ctx, req, resp)
				},
			)

			withCache := newWithCache(t, handler, ctry, tc.ctrySubnet, 0, false)
			ri := &agd.RequestInfo{
				Location: &geoip.Location{
					Country: ctry,
				},
				ECS:      tc.wantECS,
				Host:     tc.req.Question[0].Name,
				RemoteIP: remoteIP,
			}

			var msg *dns.Msg
			for i := 0; i < N; i++ {
				msg = exchange(t, ri, withCache, tc.req)
			}
			require.NotNil(t, msg)
			assert.Equal(t, 1, numReq)

			require.NotEmpty(t, msg.Answer)
			assert.Equal(t, defaultTTL, msg.Answer[0].Header().Ttl)

			assertEDNSOpt(t, tc.wantECS, msg.IsEdns0())
		})
	}
}

// assertEDNSOpt is a helper function that checks ECS and EDNS0 options.
func assertEDNSOpt(t *testing.T, ecs *agd.ECS, edns *dns.OPT) {
	t.Helper()

	if ecs == nil {
		if edns != nil {
			assert.Empty(t, edns.Option)
		}

		return
	}

	require.Len(t, edns.Option, 1)
	subnetOpt := testutil.RequireTypeAssert[*dns.EDNS0_SUBNET](t, edns.Option[0])

	assert.Equal(t, net.IP(ecs.Subnet.Addr().AsSlice()), subnetOpt.Address)
	assert.Equal(t, uint8(ecs.Subnet.Bits()), subnetOpt.SourceNetmask)
	assert.Equal(t, uint8(ecs.Subnet.Bits()), subnetOpt.SourceScope)
}

func TestMiddleware_Wrap_ecsOrder(t *testing.T) {
	// Helper values and functions

	reqNoECS := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
	reqNoECS.SetEdns0(dnsmsg.DefaultEDNSUDPSize, false)

	const prefixLen = 24

	reqWithECS := reqNoECS.Copy()
	opt := testutil.RequireTypeAssert[*dns.OPT](t, reqWithECS.Extra[len(reqWithECS.Extra)-1])
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        uint16(netutil.AddrFamilyIPv4),
		SourceNetmask: prefixLen,
		SourceScope:   0,
		Address:       netip.PrefixFrom(remoteIP, prefixLen).Masked().Addr().AsSlice(),
	})

	reqZeroECS := reqNoECS.Copy()
	opt = testutil.RequireTypeAssert[*dns.OPT](t, reqZeroECS.Extra[len(reqZeroECS.Extra)-1])
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        uint16(netutil.AddrFamilyIPv4),
		SourceNetmask: 0,
		SourceScope:   0,
		Address:       netutil.IPv4Zero(),
	})

	const ctry = geoip.CountryAD

	ctrySubnet := netip.PrefixFrom(remoteIP, 16).Masked()
	ctryECS := dnsservertest.NewECSExtra(
		ctrySubnet.Addr().AsSlice(),
		uint16(netutil.AddrFamilyIPv4),
		prefixLen,
		16,
	)
	zeroECS := dnsservertest.NewECSExtra(netutil.IPv4Zero(), uint16(netutil.AddrFamilyIPv4), 0, 0)

	answerA := dnsservertest.NewA(reqHostname, defaultTTL, netip.MustParseAddr("1.2.3.4"))
	answerB := dnsservertest.NewA(reqHostname, defaultTTL, netip.MustParseAddr("5.6.7.8"))

	// Tests

	testCases := []struct {
		name     string
		sequence sequence
	}{{
		name: "no_ecs_first",
		sequence: sequence{{
			answer:  answerA,
			extra:   ctryECS,
			msg:     reqNoECS,
			wantAns: []dns.RR{answerA},
		}, {
			answer:  nil,
			extra:   nil,
			msg:     reqWithECS,
			wantAns: []dns.RR{answerA},
		}},
	}, {
		name: "ecs_first",
		sequence: sequence{{
			answer:  answerA,
			extra:   ctryECS,
			msg:     reqWithECS,
			wantAns: []dns.RR{answerA},
		}, {
			answer:  nil,
			extra:   nil,
			msg:     reqNoECS,
			wantAns: []dns.RR{answerA},
		}},
	}, {
		name: "zero_after_no_ecs",
		sequence: sequence{{
			answer:  answerA,
			extra:   ctryECS,
			msg:     reqNoECS,
			wantAns: []dns.RR{answerA},
		}, {
			answer:  answerB,
			extra:   zeroECS,
			msg:     reqZeroECS,
			wantAns: []dns.RR{answerB},
		}},
	}, {
		name: "different_caches",
		sequence: sequence{{
			answer:  answerA,
			extra:   ctryECS,
			msg:     reqWithECS,
			wantAns: []dns.RR{answerA},
		}, {
			answer:  answerB,
			extra:   zeroECS,
			msg:     reqZeroECS,
			wantAns: []dns.RR{answerB},
		}, {
			answer:  nil,
			extra:   nil,
			msg:     reqWithECS,
			wantAns: []dns.RR{answerA},
		}, {
			answer:  nil,
			extra:   nil,
			msg:     reqZeroECS,
			wantAns: []dns.RR{answerB},
		}},
	}, {
		name: "no_ecs_upstream",
		sequence: sequence{{
			answer:  answerA,
			extra:   zeroECS,
			msg:     reqZeroECS,
			wantAns: []dns.RR{answerA},
		}, {
			answer:  answerB,
			extra:   zeroECS,
			msg:     reqNoECS,
			wantAns: []dns.RR{answerB},
		}, {
			answer:  nil,
			extra:   nil,
			msg:     reqZeroECS,
			wantAns: []dns.RR{answerA},
		}, {
			answer:  nil,
			extra:   nil,
			msg:     reqNoECS,
			wantAns: []dns.RR{answerB},
		}},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.sequence.run(t, ctry, ctrySubnet)
		})
	}
}

// request is a single request in a sequence.  answer and extra are
// prerequisites for configuring handler's response before resolving msg,
// those should be nil when the response is expected to come from cache.
type request = struct {
	answer  dns.RR
	extra   dns.RR
	msg     *dns.Msg
	wantAns []dns.RR
}

// sequence is a list of requests.
type sequence []request

// run is a helper method for testing ECS cache middleware with sequence of
// ordered requests.
func (s sequence) run(t *testing.T, ctry geoip.Country, ctrySubnet netip.Prefix) {
	t.Helper()

	const respSendTimeout = 1 * time.Second

	newResp := func(t *testing.T, req *dns.Msg, answer, extra dns.RR) (resp *dns.Msg) {
		t.Helper()

		return dnsservertest.NewResp(
			dns.RcodeSuccess,
			req,
			dnsservertest.SectionAnswer{answer},
			dnsservertest.SectionExtra{extra},
		)
	}

	pt := testutil.PanicT{}
	respCh := make(chan *dns.Msg, 1)
	handler := dnsserver.HandlerFunc(
		func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
			resp, ok := testutil.RequireReceive(pt, respCh, respSendTimeout)
			require.True(pt, ok)

			return rw.WriteMsg(ctx, req, resp)
		},
	)

	withCache := newWithCache(t, handler, ctry, ctrySubnet, 0, false)

	for i, req := range s {
		if req.answer != nil && req.extra != nil {
			resp := newResp(t, req.msg, req.answer, req.extra)
			testutil.RequireSend(t, respCh, resp, respSendTimeout)
		}

		subnet, _, err := dnsmsg.ECSFromMsg(req.msg)
		require.NoError(t, err)

		ri := &agd.RequestInfo{
			Location: &geoip.Location{Country: ctry},
			ECS:      nil,
			Host:     req.msg.Question[0].Name,
			RemoteIP: remoteIP,
		}
		if subnet != (netip.Prefix{}) {
			ri.ECS = &agd.ECS{Subnet: subnet, Scope: 0}
		}

		// Make sure each step succeeded.
		require.True(t, t.Run(fmt.Sprintf("step_%d", i), func(t *testing.T) {
			got := exchange(t, ri, withCache, req.msg)
			assert.Equal(t, req.wantAns, got.Answer)
		}))
	}
}

// exchange resolves req with h using context with ri.
func exchange(
	t testing.TB,
	ri *agd.RequestInfo,
	h dnsserver.Handler,
	req *dns.Msg,
) (resp *dns.Msg) {
	t.Helper()

	// TODO(a.garipov): Propose netip.Addr.WithPort.
	addr := &net.UDPAddr{IP: remoteIP.AsSlice(), Port: 53}
	nrw := dnsserver.NewNonWriterResponseWriter(addr, addr)

	ctx := agd.ContextWithRequestInfo(context.Background(), ri)
	err := h.ServeDNS(ctx, nrw, req)
	require.NoError(t, err)

	msg := nrw.Msg()
	require.NotNil(t, msg)

	return msg
}

// newWithCache is a helper constructor of a handler for tests.
func newWithCache(
	t testing.TB,
	h dnsserver.Handler,
	wantCtry geoip.Country,
	geoIPNet netip.Prefix,
	minTTL time.Duration,
	useTTLOverride bool,
) (wrapped dnsserver.Handler) {
	t.Helper()

	pt := testutil.PanicT{}

	// TODO(a.garipov): Actually test ASNs once we have the data.
	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			l *geoip.Location,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			require.Equal(pt, wantCtry, l.Country)

			return geoIPNet, nil
		},
		OnData: func(_ string, _ netip.Addr) (_ *geoip.Location, _ error) {
			panic("not implemented")
		},
	}

	return dnsserver.WithMiddlewares(
		h,
		ecscache.NewMiddleware(&ecscache.MiddlewareConfig{
			Cloner:         agdtest.NewCloner(),
			GeoIP:          geoIP,
			Size:           100,
			ECSSize:        100,
			MinTTL:         minTTL,
			UseTTLOverride: useTTLOverride,
		}),
	)
}
