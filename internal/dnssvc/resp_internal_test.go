package dnssvc

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFilteredResp(t *testing.T) {
	const (
		respTTL = 60
	)

	const fltRespTTL = agdtest.FilteredResponseTTLSec
	respIP := netip.MustParseAddr("1.2.3.4")
	rewrIP := netip.MustParseAddr("5.6.7.8")
	blockIP := netip.IPv4Unspecified()

	const domain = "example.com"
	req := dnsservertest.NewReq(domain, dns.TypeA, dns.ClassINET)
	rewrResp := dnsservertest.NewResp(dns.RcodeSuccess, req)
	rewrResp.Answer = append(rewrResp.Answer, dnsservertest.NewA(domain, fltRespTTL, rewrIP))

	testCases := []struct {
		reqRes  filter.Result
		respRes filter.Result
		wantIP  netip.Addr
		name    string
		wantTTL uint32
	}{{
		reqRes:  nil,
		respRes: nil,
		wantIP:  respIP,
		name:    "not_filtered",
		wantTTL: respTTL,
	}, {
		reqRes:  &filter.ResultAllowed{},
		respRes: nil,
		wantIP:  respIP,
		name:    "allowed_req",
		wantTTL: respTTL,
	}, {
		reqRes:  &filter.ResultBlocked{},
		respRes: nil,
		wantIP:  blockIP,
		name:    "blocked_req",
		wantTTL: fltRespTTL,
	}, {
		reqRes:  &filter.ResultModified{Msg: rewrResp},
		respRes: nil,
		wantIP:  rewrIP,
		name:    "modified_req",
		wantTTL: fltRespTTL,
	}, {
		reqRes:  nil,
		respRes: &filter.ResultAllowed{},
		wantIP:  respIP,
		name:    "allowed_resp",
		wantTTL: respTTL,
	}, {
		reqRes:  nil,
		respRes: &filter.ResultBlocked{},
		wantIP:  blockIP,
		name:    "blocked_resp",
		wantTTL: fltRespTTL,
	}, {
		reqRes:  nil,
		respRes: &filter.ResultModified{Msg: rewrResp},
		wantIP:  rewrIP,
		name:    "modified_resp",
		wantTTL: fltRespTTL,
	}}

	ctx := context.Background()
	ri := &agd.RequestInfo{
		Messages: agdtest.NewConstructor(),
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(nil, nil)
			resp := dnsservertest.NewResp(dns.RcodeSuccess, req)
			resp.Answer = append(resp.Answer, dnsservertest.NewA(domain, respTTL, respIP))

			written, err := writeFilteredResp(ctx, ri, rw, req, resp, tc.reqRes, tc.respRes)
			require.NoError(t, err)
			require.NotNil(t, written)

			actuallyWritten := rw.Msg()
			assert.Equal(t, written, actuallyWritten)

			require.Len(t, written.Answer, 1)

			ans := written.Answer[0]
			assert.Equal(t, tc.wantTTL, ans.Header().Ttl)

			a := testutil.RequireTypeAssert[*dns.A](t, ans)

			assert.Equal(t, net.IP(tc.wantIP.AsSlice()), a.A)
		})
	}
}
