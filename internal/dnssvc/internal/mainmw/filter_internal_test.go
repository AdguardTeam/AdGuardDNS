package mainmw

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(a.garipov): Rewrite into cases in external tests.
func TestMiddleware_setFilteredResponse(t *testing.T) {
	const (
		respTTL = 60
	)

	const fltRespTTL = agdtest.FilteredResponseTTLSec
	respIP := netip.MustParseAddr("1.2.3.4")
	rewrIP := netip.MustParseAddr("5.6.7.8")
	blockIP := netip.IPv4Unspecified()

	const domain = "example.com"
	origReq := dnsservertest.NewReq(domain, dns.TypeA, dns.ClassINET)
	rewrResp := dnsservertest.NewResp(dns.RcodeSuccess, origReq)
	rewrResp.Answer = append(rewrResp.Answer, dnsservertest.NewA(domain, fltRespTTL, rewrIP))

	mw := &Middleware{
		errColl: agdtest.NewErrorCollector(),
	}

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
		reqRes:  &filter.ResultModifiedResponse{Msg: rewrResp},
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
	}}

	ri := &agd.RequestInfo{
		Messages: agdtest.NewConstructor(t),
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			origResp := dnsservertest.NewResp(dns.RcodeSuccess, origReq)
			origResp.Answer = append(origResp.Answer, dnsservertest.NewA(domain, respTTL, respIP))

			ctx := context.Background()

			fctx := &filteringContext{
				originalRequest:  origReq,
				originalResponse: origResp,
				requestResult:    tc.reqRes,
				responseResult:   tc.respRes,
			}

			mw.setFilteredResponse(ctx, fctx, ri)

			filtered := fctx.filteredResponse
			require.NotNil(t, filtered)
			require.Len(t, filtered.Answer, 1)

			ans := filtered.Answer[0]
			assert.Equal(t, tc.wantTTL, ans.Header().Ttl)

			a := testutil.RequireTypeAssert[*dns.A](t, ans)

			assert.Equal(t, net.IP(tc.wantIP.AsSlice()), a.A)
		})
	}

	t.Run("modified_resp", func(t *testing.T) {
		wantPanicMsg := (&agd.ArgumentError{
			Name:    "respRes",
			Message: fmt.Sprintf("unexpected type %T", &filter.ResultModifiedResponse{}),
		}).Error()

		assert.PanicsWithError(t, wantPanicMsg, func() {
			fctx := &filteringContext{
				requestResult:  nil,
				responseResult: &filter.ResultModifiedResponse{Msg: rewrResp},
			}

			mw.setFilteredResponse(context.Background(), fctx, ri)
		})
	})
}
