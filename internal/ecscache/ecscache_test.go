package ecscache_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

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
const defaultTTL = 3600

// remoteIP is the IP to use for tests.
var remoteIP = netip.MustParseAddr("1.2.3.4")

func TestMiddleware_Wrap_noECS(t *testing.T) {
	aReq := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
	cnameReq := dnsservertest.NewReq(reqHostname, dns.TypeCNAME, dns.ClassINET)
	cnameAns := dnsservertest.RRSection{
		RRs: []dns.RR{dnsservertest.NewCNAME(reqHostname, defaultTTL, reqCNAME)},
		Sec: dnsservertest.SectionAnswer,
	}
	soaNS := dnsservertest.RRSection{
		RRs: []dns.RR{dnsservertest.NewSOA(reqHostname, defaultTTL, reqNS1, reqNS2)},
		Sec: dnsservertest.SectionNs,
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
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.RRSection{
			RRs: []dns.RR{dnsservertest.NewA(reqHostname, defaultTTL, net.IP{1, 2, 3, 4})},
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
		resp: dnsservertest.NewResp(dns.RcodeNameError, aReq, dnsservertest.RRSection{
			RRs: []dns.RR{dnsservertest.NewNS(reqHostname, defaultTTL, reqNS1)},
			Sec: dnsservertest.SectionNs,
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
		resp: dnsservertest.NewResp(dns.RcodeSuccess, cnameReq, dnsservertest.RRSection{
			RRs: []dns.RR{dnsservertest.NewCNAME(reqHostname, defaultTTL, reqCNAME)},
		}),
		name:       "simple_cname_ans",
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.RRSection{
			RRs: []dns.RR{dnsservertest.NewA(reqHostname, 0, net.IP{1, 2, 3, 4})},
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
			ctx := agd.ContextWithRequestInfo(context.Background(), &agd.RequestInfo{
				Host:     tc.req.Question[0].Name,
				RemoteIP: remoteIP,
			})

			var err error
			var nrw *dnsserver.NonWriterResponseWriter
			for i := 0; i < N; i++ {
				// TODO(a.garipov): Propose netip.Addr.WithPort.
				addr := &net.UDPAddr{IP: remoteIP.AsSlice(), Port: 53}
				nrw = dnsserver.NewNonWriterResponseWriter(addr, addr)
				err = withCache.ServeDNS(ctx, nrw, tc.req)
			}

			require.NoError(t, err)

			msg := nrw.Msg()
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
	subnet := netip.PrefixFrom(netip.AddrFrom4(*(*[4]byte)(ip)), prefixLen)
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        uint16(netutil.AddrFamilyIPv4),
		SourceNetmask: prefixLen,
		SourceScope:   0,
		Address:       ip,
	})

	const ctry = agd.CountryAD
	defaultCtrySubnet := netip.MustParsePrefix("1.2.0.0/16")
	ecsExtra := dnsservertest.NewECSExtra(net.IP{1, 2, 0, 0}, uint16(netutil.AddrFamilyIPv4), 20, 20)

	testCases := []struct {
		req        *dns.Msg
		resp       *dns.Msg
		ecs        *agd.ECS
		name       string
		ctrySubnet netip.Prefix
		wantNumReq int
		wantTTL    uint32
	}{{
		req: aReq,
		resp: dnsservertest.NewResp(
			dns.RcodeSuccess,
			aReq,
			dnsservertest.RRSection{
				RRs: []dns.RR{dnsservertest.NewA(reqHostname, defaultTTL, net.IP{1, 2, 3, 4})},
				Sec: dnsservertest.SectionAnswer,
			},
			dnsservertest.RRSection{
				RRs: []dns.RR{ecsExtra},
				Sec: dnsservertest.SectionExtra,
			},
		),
		ecs: &agd.ECS{
			Location: &agd.Location{
				Country: ctry,
			},
			Subnet: subnet,
			Scope:  0,
		},
		name:       "with_country",
		ctrySubnet: defaultCtrySubnet,
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(
			dns.RcodeSuccess,
			aReq,
			dnsservertest.RRSection{
				RRs: []dns.RR{dnsservertest.NewA(reqHostname, defaultTTL, net.IP{1, 2, 3, 4})},
				Sec: dnsservertest.SectionAnswer,
			},
			dnsservertest.RRSection{
				RRs: []dns.RR{ecsExtra},
				Sec: dnsservertest.SectionExtra,
			},
		),
		ecs: &agd.ECS{
			Location: &agd.Location{
				Country: ctry,
			},
			Subnet: subnet,
			Scope:  0,
		},
		name:       "no_country",
		ctrySubnet: netutil.ZeroPrefix(netutil.AddrFamilyIPv4),
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req: aReqNoECS,
		resp: dnsservertest.NewResp(
			dns.RcodeSuccess,
			aReq,
			dnsservertest.RRSection{
				RRs: []dns.RR{dnsservertest.NewA(reqHostname, defaultTTL, net.IP{1, 2, 3, 4})},
				Sec: dnsservertest.SectionAnswer,
			},
			dnsservertest.RRSection{
				RRs: []dns.RR{ecsExtra},
				Sec: dnsservertest.SectionExtra,
			},
		),
		ecs:        nil,
		name:       "edns_no_ecs",
		ctrySubnet: defaultCtrySubnet,
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(
			dns.RcodeSuccess,
			aReq,
			dnsservertest.RRSection{
				RRs: []dns.RR{dnsservertest.NewA(reqHostname, defaultTTL, net.IP{1, 2, 3, 4})},
				Sec: dnsservertest.SectionAnswer,
			},
			dnsservertest.RRSection{
				RRs: []dns.RR{ecsExtra},
				Sec: dnsservertest.SectionExtra,
			},
		),
		ecs:        nil,
		name:       "country_from_ip",
		ctrySubnet: defaultCtrySubnet,
		wantNumReq: 1,
		wantTTL:    defaultTTL,
	}}

	const N = 5
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			numReq := 0
			handler := dnsserver.HandlerFunc(
				func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
					numReq++

					return rw.WriteMsg(ctx, req, tc.resp)
				},
			)

			withCache := newWithCache(t, handler, ctry, tc.ctrySubnet)
			ctx := agd.ContextWithRequestInfo(context.Background(), &agd.RequestInfo{
				Location: &agd.Location{
					Country: ctry,
				},
				ECS:      tc.ecs,
				Host:     tc.req.Question[0].Name,
				RemoteIP: remoteIP,
			})

			var nrw *dnsserver.NonWriterResponseWriter
			var msg *dns.Msg
			var respOpt *dns.OPT
			for i := 0; i < N; i++ {
				addr := &net.UDPAddr{IP: remoteIP.AsSlice(), Port: 53}
				nrw = dnsserver.NewNonWriterResponseWriter(addr, addr)
				err := withCache.ServeDNS(ctx, nrw, tc.req)
				require.NoError(t, err)

				msg = nrw.Msg()
				respOpt = msg.IsEdns0()
				if tc.ecs == nil && respOpt != nil {
					require.Empty(t, respOpt.Option)
				}
			}

			require.NotNil(t, msg)

			if tc.ecs == nil {
				return
			}

			assert.Equal(t, tc.wantNumReq, numReq)

			if len(msg.Answer) > 0 {
				assert.Equal(t, tc.wantTTL, msg.Answer[0].Header().Ttl)
			}

			require.NotNil(t, respOpt)
			require.Len(t, respOpt.Option, 1)

			subnetOpt := testutil.RequireTypeAssert[*dns.EDNS0_SUBNET](t, respOpt.Option[0])

			assert.Equal(t, ip, subnetOpt.Address)
			assert.Equal(t, uint8(prefixLen), subnetOpt.SourceNetmask)
			assert.Equal(t, uint8(prefixLen), subnetOpt.SourceScope)
		})
	}
}

// newWithCache is a helper constructor of a handler for tests.
func newWithCache(
	t testing.TB,
	h dnsserver.Handler,
	wantCtry agd.Country,
	geoIPNet netip.Prefix,
) (wrapped dnsserver.Handler) {
	t.Helper()

	// TODO(a.garipov): Actually test ASNs once we have the data.
	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			ctry agd.Country,
			_ agd.ASN,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			t.Helper()

			assert.Equal(t, wantCtry, ctry)

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
