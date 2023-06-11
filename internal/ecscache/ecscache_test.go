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
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	const N = 5
	testCases := []struct {
		req        *dns.Msg
		resp       *dns.Msg
		name       string
		wantNumReq int
		wantTTL    uint32
	}{{
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, defaultTTL, net.IP{1, 2, 3, 4}),
		}),
		name:       "simple_a",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq),
		name:       "empty_answer",
		wantNumReq: N,
		wantTTL:    0,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, soaNS),
		name:       "authoritative_nodata",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, cnameAns, soaNS),
		name:       "nodata_with_cname",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, cnameAns),
		name:       "nodata_with_cname_no_soa",
		wantNumReq: N,
		wantTTL:    defaultTTL,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeNameError, aReq, dnsservertest.SectionNs{
			dnsservertest.NewNS(reqHostname, defaultTTL, reqNS1),
		}),
		name: "non_authoritative_nxdomain",
		// TODO(ameshkov): Consider https://datatracker.ietf.org/doc/html/rfc2308#section-3.
		wantNumReq: 1,
		wantTTL:    0,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeNameError, aReq, soaNS),
		name:       "authoritative_nxdomain",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeServerFailure, aReq),
		name:       "simple_server_failure",
		wantNumReq: 1,
		wantTTL:    ecscache.ServFailMaxCacheTTL,
	}, {
		req: cnameReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, cnameReq, dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(reqHostname, defaultTTL, reqCNAME),
		}),
		name:       "simple_cname_ans",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 0, net.IP{1, 2, 3, 4}),
		}),
		name:       "expired_one",
		wantNumReq: N,
		wantTTL:    0,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeNotImplemented, aReq, soaNS),
		name:       "unexpected_response",
		wantNumReq: N,
		wantTTL:    0,
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

			withCache := newWithCache(
				t,
				handler,
				agd.CountryNone,
				netutil.ZeroPrefix(netutil.AddrFamilyIPv4),
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

func TestMiddleware_Wrap_ecs(t *testing.T) {
	aReqNoECS := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
	aReqNoECS.SetEdns0(dnsmsg.DefaultEDNSUDPSize, false)

	aReq := aReqNoECS.Copy()
	opt := aReq.Extra[len(aReq.Extra)-1].(*dns.OPT)

	const prefixLen = 24

	ip := net.IP{1, 2, 3, 0}
	subnet := netip.PrefixFrom(netip.AddrFrom4([4]byte(ip)), prefixLen)
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        uint16(netutil.AddrFamilyIPv4),
		SourceNetmask: prefixLen,
		SourceScope:   0,
		Address:       ip,
	})

	const ctry = agd.CountryAD

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
		ecs        *agd.ECS
		ctrySubnet netip.Prefix
		name       string
	}{{
		req:     aReq,
		respECS: ecsExtra,
		ecs: &agd.ECS{
			Location: &agd.Location{
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
		ecs: &agd.ECS{
			Location: &agd.Location{
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
		ecs:        nil,
		ctrySubnet: defaultCtrySubnet,
		name:       "edns_no_ecs",
	}, {
		req:        aReq,
		respECS:    ecsExtra,
		ecs:        nil,
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
		ecs: &agd.ECS{
			Location: &agd.Location{
				Country: agd.CountryNone,
			},
			Subnet: netutil.ZeroPrefix(netutil.AddrFamilyIPv4),
			Scope:  0,
		},
		ctrySubnet: defaultCtrySubnet,
		name:       "zero_ecs",
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
					net.IP{1, 2, 3, 4},
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

			withCache := newWithCache(t, handler, ctry, tc.ctrySubnet)
			ri := &agd.RequestInfo{
				Location: &agd.Location{
					Country: ctry,
				},
				ECS:      tc.ecs,
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

			respOpt := msg.IsEdns0()
			if tc.ecs == nil {
				if respOpt != nil {
					require.Empty(t, respOpt.Option)
				}

				return
			}

			require.Len(t, respOpt.Option, 1)
			subnetOpt := testutil.RequireTypeAssert[*dns.EDNS0_SUBNET](t, respOpt.Option[0])

			assert.Equal(t, net.IP(tc.ecs.Subnet.Addr().AsSlice()), subnetOpt.Address)
			assert.Equal(t, uint8(tc.ecs.Subnet.Bits()), subnetOpt.SourceNetmask)
			assert.Equal(t, uint8(tc.ecs.Subnet.Bits()), subnetOpt.SourceScope)
		})
	}
}

func TestMiddleware_Wrap_ecsOrder(t *testing.T) {
	// Helper values and functions

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

	const ctry = agd.CountryAD

	ctrySubnet := netip.PrefixFrom(remoteIP, 16).Masked()
	ctryECS := dnsservertest.NewECSExtra(
		ctrySubnet.Addr().AsSlice(),
		uint16(netutil.AddrFamilyIPv4),
		prefixLen,
		16,
	)
	zeroECS := dnsservertest.NewECSExtra(netutil.IPv4Zero(), uint16(netutil.AddrFamilyIPv4), 0, 0)

	pt := testutil.PanicT{}
	respCh := make(chan *dns.Msg, 1)
	handler := dnsserver.HandlerFunc(
		func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
			resp, ok := testutil.RequireReceive(pt, respCh, respSendTimeout)
			require.True(pt, ok)

			return rw.WriteMsg(ctx, req, resp)
		},
	)

	answerA := dnsservertest.NewA(reqHostname, defaultTTL, net.IP{1, 2, 3, 4})
	answerB := dnsservertest.NewA(reqHostname, defaultTTL, net.IP{5, 6, 7, 8})

	// Tests

	// request is a single request in a sequence.  answer and extra are
	// prerequisites for configuring handler's response before resolving msg,
	// those should be nil when the response is expected to come from cache.
	type request = struct {
		answer  dns.RR
		extra   dns.RR
		msg     *dns.Msg
		wantAns []dns.RR
	}

	testCases := []struct {
		name     string
		sequence []request
	}{{
		name: "no_ecs_first",
		sequence: []request{{
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
		sequence: []request{{
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
		sequence: []request{{
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
		sequence: []request{{
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
		sequence: []request{{
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
		withCache := newWithCache(t, handler, ctry, ctrySubnet)

		t.Run(tc.name, func(t *testing.T) {
			for i, req := range tc.sequence {
				if req.answer != nil && req.extra != nil {
					resp := newResp(t, req.msg, req.answer, req.extra)
					testutil.RequireSend(t, respCh, resp, respSendTimeout)
				}

				subnet, _, err := dnsmsg.ECSFromMsg(req.msg)
				require.NoError(t, err)

				ri := &agd.RequestInfo{
					Location: &agd.Location{Country: ctry},
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
		})
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
	wantCtry agd.Country,
	geoIPNet netip.Prefix,
) (wrapped dnsserver.Handler) {
	t.Helper()

	pt := testutil.PanicT{}

	// TODO(a.garipov): Actually test ASNs once we have the data.
	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			ctry agd.Country,
			_ agd.ASN,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			require.Equal(pt, wantCtry, ctry)

			return geoIPNet, nil
		},
		OnData: func(_ string, _ netip.Addr) (_ *agd.Location, _ error) {
			panic("not implemented")
		},
	}

	return dnsserver.WithMiddlewares(
		h,
		ecscache.NewMiddleware(&ecscache.MiddlewareConfig{
			GeoIP:   geoIP,
			Size:    100,
			ECSSize: 100,
		}),
	)
}
