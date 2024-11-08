package preupstream_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/preupstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreUpstreamMwHandler_ServeDNS_androidMetric(t *testing.T) {
	t.Parallel()

	ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
	mw := preupstream.New(ctx, &preupstream.Config{
		DB: dnsdb.Empty{},
	})

	req := dnsservertest.CreateMessage(dnssvctest.DomainFQDN, dns.TypeA)
	defaultResp := new(dns.Msg).SetReply(req)

	ctx = agd.ContextWithRequestInfo(ctx, &agd.RequestInfo{})

	ipA := dnssvctest.ClientAddr
	ipB := ipA.Next()

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
		req:      dnsservertest.CreateMessage(dnssvctest.DomainFQDN, dns.TypeA),
		resp:     dnsmsg.Clone(defaultResp),
		wantName: dnssvctest.DomainFQDN,
		wantAns:  nil,
	}, {
		name:     "android-tls-metric",
		req:      dnsservertest.CreateMessage("12345678"+tlsDomain, dns.TypeA),
		resp:     dnsmsg.Clone(defaultResp),
		wantName: "00000000" + tlsDomain,
		wantAns:  nil,
	}, {
		name:     "android-https-metric",
		req:      dnsservertest.CreateMessage("123456"+httpsDomain, dns.TypeA),
		resp:     dnsmsg.Clone(defaultResp),
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
			t.Parallel()

			handler := dnsserver.HandlerFunc(func(
				ctx context.Context,
				rw dnsserver.ResponseWriter,
				req *dns.Msg,
			) error {
				assert.Equal(t, tc.wantName, req.Question[0].Name)

				return rw.WriteMsg(ctx, req, tc.resp)
			})

			h := mw.Wrap(handler)

			rw := dnsserver.NewNonWriterResponseWriter(nil, dnssvctest.ClientTCPAddr)

			err := h.ServeDNS(ctx, rw, tc.req)
			require.NoError(t, err)

			msg := rw.Msg()
			require.NotNil(t, msg)

			assert.Equal(t, tc.wantAns, msg.Answer)
		})
	}
}
