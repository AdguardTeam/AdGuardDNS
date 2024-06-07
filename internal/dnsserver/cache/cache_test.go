package cache_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_Wrap(t *testing.T) {
	const (
		servFailMaxCacheTTL = 30

		reqHostname = "example.com"
		reqCname    = "cname.example.com"
		reqNs1      = "ns1.example.com"
		reqNs2      = "ns2.example.com"

		defaultTTL uint32 = 3600
	)

	reqAddr := netip.MustParseAddr("1.2.3.4")
	testTTL := 60 * time.Second

	aReq := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
	cnameReq := dnsservertest.NewReq(reqHostname, dns.TypeCNAME, dns.ClassINET)
	cnameAns := dnsservertest.SectionAnswer{dnsservertest.NewCNAME(reqHostname, defaultTTL, reqCname)}
	soaNs := dnsservertest.SectionNs{dnsservertest.NewSOA(reqHostname, defaultTTL, reqNs1, reqNs2)}

	const N = 5
	testCases := []struct {
		req        *dns.Msg
		resp       *dns.Msg
		name       string
		minTTL     *time.Duration
		wantNumReq int
		wantTTL    uint32
	}{{
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, defaultTTL, reqAddr),
		}),
		name:       "simple_a",
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq),
		name:       "empty_answer",
		wantNumReq: N,
		minTTL:     nil,
		wantTTL:    0,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, soaNs),
		name:       "authoritative_nodata",
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, cnameAns, soaNs),
		name:       "nodata_with_cname",
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, cnameAns),
		name:       "nodata_with_cname_no_soa",
		wantNumReq: N,
		minTTL:     nil,
		wantTTL:    defaultTTL,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeNameError, aReq, dnsservertest.SectionNs{
			dnsservertest.NewNS(reqHostname, defaultTTL, reqNs1),
		}),
		name: "non_authoritative_nxdomain",
		// TODO(ameshkov): Consider https://datatracker.ietf.org/doc/html/rfc2308#section-3.
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeNameError, aReq, soaNs),
		name:       "authoritative_nxdomain",
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    defaultTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeServerFailure, aReq),
		name:       "simple_server_failure",
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    servFailMaxCacheTTL,
	}, {
		req: cnameReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, cnameReq, dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(reqHostname, defaultTTL, reqCname),
		}),
		name:       "simple_cname_ans",
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    defaultTTL,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 0, reqAddr),
		}),
		name:       "expired_one",
		wantNumReq: N,
		minTTL:     nil,
		wantTTL:    0,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 10, reqAddr),
		}),
		name:       "override_ttl_ok",
		wantNumReq: 1,
		minTTL:     &testTTL,
		wantTTL:    uint32(testTTL.Seconds()),
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 1000, reqAddr),
		}),
		name:       "override_ttl_max",
		wantNumReq: 1,
		minTTL:     &testTTL,
		wantTTL:    1000,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 0, reqAddr),
		}),
		name:       "override_ttl_zero",
		wantNumReq: N,
		minTTL:     &testTTL,
		wantTTL:    0,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeServerFailure, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, servFailMaxCacheTTL, reqAddr),
		}),
		name:       "override_ttl_servfail",
		wantNumReq: 1,
		minTTL:     nil,
		wantTTL:    servFailMaxCacheTTL,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeNotImplemented, aReq, soaNs),
		name:       "unexpected_response",
		wantNumReq: N,
		minTTL:     nil,
		wantTTL:    defaultTTL,
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

			withCache := dnsserver.WithMiddlewares(
				handler,
				cache.NewMiddleware(&cache.MiddlewareConfig{
					Size:           100,
					MinTTL:         minTTL,
					UseTTLOverride: tc.minTTL != nil,
				}),
			)

			var err error
			var nrw *dnsserver.NonWriterResponseWriter
			for range N {
				addr := &net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 53}
				nrw = dnsserver.NewNonWriterResponseWriter(addr, addr)
				err = withCache.ServeDNS(context.Background(), nrw, tc.req)
			}

			require.NoError(t, err)

			m := nrw.Msg()
			assert.Equal(t, tc.resp, m)
			assert.Equal(t, tc.wantNumReq, numReq)

			if len(m.Answer) > 0 {
				assert.Equal(t, tc.wantTTL, m.Answer[0].Header().Ttl)
			}
		})
	}
}
