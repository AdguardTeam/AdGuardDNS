package cache_test

import (
	"context"
	"net"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_Wrap(t *testing.T) {
	const (
		reqHostname = "example.com"
		reqCname    = "cname.example.com"
		reqNs1      = "ns1.example.com"
		reqNs2      = "ns2.example.com"
	)

	aReq := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
	cnameReq := dnsservertest.NewReq(reqHostname, dns.TypeCNAME, dns.ClassINET)
	cnameAns := dnsservertest.SectionAnswer{dnsservertest.NewCNAME(reqHostname, 3600, reqCname)}
	soaNs := dnsservertest.SectionNs{dnsservertest.NewSOA(reqHostname, 3600, reqNs1, reqNs2)}

	const N = 5
	testCases := []struct {
		req        *dns.Msg
		resp       *dns.Msg
		name       string
		wantNumReq int
	}{{
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 3600, net.IP{1, 2, 3, 4}),
		}),
		name:       "simple_a",
		wantNumReq: 1,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq),
		name:       "empty_answer",
		wantNumReq: N,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, soaNs),
		name:       "authoritative_nodata",
		wantNumReq: 1,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, cnameAns, soaNs),
		name:       "nodata_with_cname",
		wantNumReq: 1,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeSuccess, aReq, cnameAns),
		name:       "nodata_with_cname_no_soa",
		wantNumReq: N,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeNameError, aReq, dnsservertest.SectionNs{
			dnsservertest.NewNS(reqHostname, 3600, reqNs1),
		}),
		name: "non_authoritative_nxdomain",
		// TODO(ameshkov): Consider https://datatracker.ietf.org/doc/html/rfc2308#section-3.
		wantNumReq: 1,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeNameError, aReq, soaNs),
		name:       "authoritative_nxdomain",
		wantNumReq: 1,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeServerFailure, aReq),
		name:       "simple_server_failure",
		wantNumReq: 1,
	}, {
		req: cnameReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, cnameReq, dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(reqHostname, 3600, reqCname),
		}),
		name:       "simple_cname_ans",
		wantNumReq: 1,
	}, {
		req: aReq,
		resp: dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
			dnsservertest.NewA(reqHostname, 0, net.IP{1, 2, 3, 4}),
		}),
		name:       "expired_one",
		wantNumReq: N,
	}, {
		req:        aReq,
		resp:       dnsservertest.NewResp(dns.RcodeNotImplemented, aReq, soaNs),
		name:       "unexpected_response",
		wantNumReq: N,
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

			withCache := dnsserver.WithMiddlewares(
				handler,
				cache.NewMiddleware(&cache.MiddlewareConfig{
					Size: 100,
				}),
			)

			var err error
			var nrw *dnsserver.NonWriterResponseWriter
			for i := 0; i < N; i++ {
				addr := &net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 53}
				nrw = dnsserver.NewNonWriterResponseWriter(addr, addr)
				err = withCache.ServeDNS(context.Background(), nrw, tc.req)
			}

			require.NoError(t, err)

			assert.Equal(t, tc.resp, nrw.Msg())
			assert.Equal(t, tc.wantNumReq, numReq)
		})
	}
}
