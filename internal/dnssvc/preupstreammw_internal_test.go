package dnssvc

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	reqHostname = "example.com."
	defaultTTL  = 3600
)

func TestPreUpstreamMwHandler_ServeDNS_withCache(t *testing.T) {
	remoteIP := netip.MustParseAddr("1.2.3.4")
	aReq := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
	respIP := remoteIP.AsSlice()

	resp := dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
		dnsservertest.NewA(reqHostname, defaultTTL, respIP),
	})
	ctx := agd.ContextWithRequestInfo(context.Background(), &agd.RequestInfo{
		Host: aReq.Question[0].Name,
	})

	const N = 5
	testCases := []struct {
		name       string
		cacheSize  int
		wantNumReq int
	}{{
		name:       "no_cache",
		cacheSize:  0,
		wantNumReq: N,
	}, {
		name:       "with_cache",
		cacheSize:  100,
		wantNumReq: 1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			numReq := 0
			handler := dnsserver.HandlerFunc(func(
				ctx context.Context,
				rw dnsserver.ResponseWriter,
				req *dns.Msg,
			) error {
				numReq++

				return rw.WriteMsg(ctx, req, resp)
			})

			mw := &preUpstreamMw{
				db:        dnsdb.Empty{},
				cacheSize: tc.cacheSize,
			}
			h := mw.Wrap(handler)

			for i := 0; i < N; i++ {
				req := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
				addr := &net.UDPAddr{IP: remoteIP.AsSlice(), Port: 53}
				nrw := dnsserver.NewNonWriterResponseWriter(addr, addr)

				err := h.ServeDNS(ctx, nrw, req)
				require.NoError(t, err)
			}

			assert.Equal(t, tc.wantNumReq, numReq)
		})
	}
}

func TestPreUpstreamMwHandler_ServeDNS_withECSCache(t *testing.T) {
	aReq := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)
	remoteIP := netip.MustParseAddr("1.2.3.4")
	subnet := netip.MustParsePrefix("1.2.3.4/24")

	const ctry = agd.CountryAD

	resp := dnsservertest.NewResp(dns.RcodeSuccess, aReq, dnsservertest.SectionAnswer{
		dnsservertest.NewA(reqHostname, defaultTTL, net.IP{1, 2, 3, 4}),
	})

	numReq := 0
	handler := dnsserver.HandlerFunc(
		func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
			numReq++

			return rw.WriteMsg(ctx, req, resp)
		},
	)

	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			ctry agd.Country,
			_ agd.ASN,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			return netip.MustParsePrefix("1.2.0.0/16"), nil
		},
		OnData: func(_ string, _ netip.Addr) (_ *agd.Location, _ error) {
			panic("not implemented")
		},
	}

	mw := &preUpstreamMw{
		db:           dnsdb.Empty{},
		geoIP:        geoIP,
		cacheSize:    100,
		ecsCacheSize: 100,
		useECSCache:  true,
	}
	h := mw.Wrap(handler)

	ctx := agd.ContextWithRequestInfo(context.Background(), &agd.RequestInfo{
		Location: &agd.Location{
			Country: ctry,
		},
		ECS: &agd.ECS{
			Location: &agd.Location{
				Country: ctry,
			},
			Subnet: subnet,
			Scope:  0,
		},
		Host:     aReq.Question[0].Name,
		RemoteIP: remoteIP,
	})

	const N = 5
	var nrw *dnsserver.NonWriterResponseWriter
	for i := 0; i < N; i++ {
		addr := &net.UDPAddr{IP: remoteIP.AsSlice(), Port: 53}
		nrw = dnsserver.NewNonWriterResponseWriter(addr, addr)
		req := dnsservertest.NewReq(reqHostname, dns.TypeA, dns.ClassINET)

		err := h.ServeDNS(ctx, nrw, req)
		require.NoError(t, err)
	}

	assert.Equal(t, 1, numReq)
}

func TestPreUpstreamMwHandler_ServeDNS_androidMetric(t *testing.T) {
	mw := &preUpstreamMw{db: dnsdb.Empty{}}

	req := dnsservertest.CreateMessage("example.com", dns.TypeA)
	resp := new(dns.Msg).SetReply(req)

	ctx := context.Background()
	ctx = dnsserver.ContextWithServerInfo(ctx, dnsserver.ServerInfo{})
	ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{})
	ctx = dnsserver.ContextWithStartTime(ctx, time.Now())
	ctx = agd.ContextWithRequestInfo(ctx, &agd.RequestInfo{})

	ipA := net.IP{1, 2, 3, 4}
	ipB := net.IP{1, 2, 3, 5}

	const ttl = 100

	const (
		httpsDomain = "-dnsohttps-ds.metric.gstatic.com."
		tlsDomain   = "-dnsotls-ds.metric.gstatic.com."
	)

	testCases := []struct {
		name     string
		req      *dns.Msg
		resp     *dns.Msg
		wantName string
		wantAns  []dns.RR
	}{{
		name:     "no_changes",
		req:      dnsservertest.CreateMessage("example.com.", dns.TypeA),
		resp:     resp,
		wantName: "example.com.",
		wantAns:  nil,
	}, {
		name:     "android-tls-metric",
		req:      dnsservertest.CreateMessage("12345678"+tlsDomain, dns.TypeA),
		resp:     resp,
		wantName: "00000000" + tlsDomain,
		wantAns:  nil,
	}, {
		name:     "android-https-metric",
		req:      dnsservertest.CreateMessage("123456"+httpsDomain, dns.TypeA),
		resp:     resp,
		wantName: "000000" + httpsDomain,
		wantAns:  nil,
	}, {
		name: "multiple_answers_metric",
		req:  dnsservertest.CreateMessage("123456"+httpsDomain, dns.TypeA),
		resp: dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.SectionAnswer{
			dnsservertest.NewA("123456"+httpsDomain, ttl, ipA),
			dnsservertest.NewA("654321"+httpsDomain, ttl, ipB),
		}),
		wantName: "000000" + httpsDomain,
		wantAns: []dns.RR{
			dnsservertest.NewA("123456"+httpsDomain, ttl, ipA),
			dnsservertest.NewA("123456"+httpsDomain, ttl, ipB),
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := dnsserver.HandlerFunc(func(
				ctx context.Context,
				rw dnsserver.ResponseWriter,
				req *dns.Msg,
			) error {
				assert.Equal(t, tc.wantName, req.Question[0].Name)

				return rw.WriteMsg(ctx, req, tc.resp)
			})

			h := mw.Wrap(handler)

			rw := dnsserver.NewNonWriterResponseWriter(nil, testRAddr)

			err := h.ServeDNS(ctx, rw, tc.req)
			require.NoError(t, err)

			msg := rw.Msg()
			require.NotNil(t, msg)

			assert.Equal(t, tc.wantAns, msg.Answer)
		})
	}
}
