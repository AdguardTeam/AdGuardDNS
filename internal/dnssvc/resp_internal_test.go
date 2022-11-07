package dnssvc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFilteredResp(t *testing.T) {
	const (
		fltRespTTL = 42
		respTTL    = 10
	)

	respIP := net.IP{1, 2, 3, 4}
	rewrIP := net.IP{5, 6, 7, 8}
	blockIP := netutil.IPv4Zero()

	const domain = "example.com"
	req := dnsservertest.NewReq(domain, dns.TypeA, dns.ClassINET)
	rewrResp := dnsservertest.NewResp(dns.RcodeSuccess, req)
	rewrResp.Answer = append(rewrResp.Answer, dnsservertest.NewA(domain, fltRespTTL, rewrIP))

	testCases := []struct {
		reqRes  filter.Result
		respRes filter.Result
		name    string
		wantIP  net.IP
		wantTTL uint32
	}{{
		reqRes:  nil,
		respRes: nil,
		name:    "not_filtered",
		wantIP:  respIP,
		wantTTL: respTTL,
	}, {
		reqRes:  &filter.ResultAllowed{},
		respRes: nil,
		name:    "allowed_req",
		wantIP:  respIP,
		wantTTL: respTTL,
	}, {
		reqRes:  &filter.ResultBlocked{},
		respRes: nil,
		name:    "blocked_req",
		wantIP:  blockIP,
		wantTTL: fltRespTTL,
	}, {
		reqRes:  &filter.ResultModified{Msg: rewrResp},
		respRes: nil,
		name:    "modified_req",
		wantIP:  rewrIP,
		wantTTL: fltRespTTL,
	}, {
		reqRes:  nil,
		respRes: &filter.ResultAllowed{},
		name:    "allowed_resp",
		wantIP:  respIP,
		wantTTL: respTTL,
	}, {
		reqRes:  nil,
		respRes: &filter.ResultBlocked{},
		name:    "blocked_resp",
		wantIP:  blockIP,
		wantTTL: fltRespTTL,
	}, {
		reqRes:  nil,
		respRes: &filter.ResultModified{Msg: rewrResp},
		name:    "modified_resp",
		wantIP:  rewrIP,
		wantTTL: fltRespTTL,
	}}

	ctx := context.Background()
	ri := &agd.RequestInfo{
		Messages: &dnsmsg.Constructor{
			FilteredResponseTTL: fltRespTTL * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(nil, nil)
			resp := dnsservertest.NewResp(dns.RcodeSuccess, req)
			resp.Answer = append(resp.Answer, dnsservertest.NewA(domain, 10, respIP))

			written, err := writeFilteredResp(ctx, ri, rw, req, resp, tc.reqRes, tc.respRes)
			require.NoError(t, err)
			require.NotNil(t, written)

			actuallyWritten := rw.Msg()
			assert.Equal(t, written, actuallyWritten)

			require.Len(t, written.Answer, 1)

			ans := written.Answer[0]
			assert.Equal(t, tc.wantTTL, ans.Header().Ttl)

			a := testutil.RequireTypeAssert[*dns.A](t, ans)

			assert.Equal(t, tc.wantIP, a.A)
		})
	}
}
