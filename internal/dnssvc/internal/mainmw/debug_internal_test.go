package mainmw

import (
	"context"
	"fmt"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTXTExtra is a helper function that converts strs into DNS TXT resource
// records with Name and Txt fields set to first and second values of each
// tuple.
func newTXTExtra(strs [][2]string) (extra []dns.RR) {
	for _, v := range strs {
		extra = append(extra, &dns.TXT{
			// TODO(a.garipov): Consider exporting dnsmsg.Constructor.newHdr and
			// using it here.
			Hdr: dns.RR_Header{
				Name:   v[0],
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassCHAOS,
				Ttl:    agdtest.FilteredResponseTTLSec,
			},
			Txt: []string{v[1]},
		})
	}

	return extra
}

// TODO(a.garipov): Rewrite into cases in external tests.
func TestMiddleware_writeDebugResponse(t *testing.T) {
	mw := &Middleware{
		messages: agdtest.NewConstructor(),
		cloner:   agdtest.NewCloner(),
		errColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) {
				panic(fmt.Errorf("unexpected error: %w", err))
			},
		},
	}

	// TODO(a.garipov): Consider moving to dnssvctest and DRY'ing with
	// mainmw_test.
	const (
		allowRule   = "||" + dnssvctest.DomainAllowed + "^"
		blockRule   = "||" + dnssvctest.DomainBlocked + "^"
		rewriteRule = "||" + dnssvctest.DomainRewritten + "^$dnsrewrite=REFUSED"
	)

	clientIPStr := dnssvctest.ClientIP.String()
	serverIPStr := dnssvctest.ServerAddr.String()

	defaultReqInfo := &agd.RequestInfo{
		Messages: agdtest.NewConstructor(),
	}

	testCases := []struct {
		name      string
		domain    string
		reqInfo   *agd.RequestInfo
		reqRes    filter.Result
		respRes   filter.Result
		wantExtra []dns.RR
	}{{
		name:    "normal",
		domain:  dnssvctest.DomainFQDN,
		reqInfo: defaultReqInfo,
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name:    "request_result_blocked",
		domain:  dnssvctest.DomainBlockedFQDN,
		reqInfo: defaultReqInfo,
		reqRes:  &filter.ResultBlocked{List: dnssvctest.FilterListID1, Rule: blockRule},
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"req.res-type.adguard-dns.com.", "blocked"},
			{"req.rule.adguard-dns.com.", blockRule},
			{"req.rule-list-id.adguard-dns.com.", dnssvctest.FilterListID1Str},
		}),
	}, {
		name:    "response_result_blocked",
		domain:  dnssvctest.DomainBlockedFQDN,
		reqInfo: defaultReqInfo,
		reqRes:  nil,
		respRes: &filter.ResultBlocked{List: dnssvctest.FilterListID2, Rule: blockRule},
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"resp.res-type.adguard-dns.com.", "blocked"},
			{"resp.rule.adguard-dns.com.", blockRule},
			{"resp.rule-list-id.adguard-dns.com.", dnssvctest.FilterListID2Str},
		}),
	}, {
		name:    "request_result_allowed",
		domain:  dnssvctest.DomainAllowedFQDN,
		reqInfo: defaultReqInfo,
		reqRes: &filter.ResultAllowed{
			Rule: allowRule,
		},
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"req.res-type.adguard-dns.com.", "allowed"},
			{"req.rule.adguard-dns.com.", allowRule},
			{"req.rule-list-id.adguard-dns.com.", ""},
		}),
	}, {
		name:    "response_result_allowed",
		domain:  dnssvctest.DomainAllowedFQDN,
		reqInfo: defaultReqInfo,
		reqRes:  nil,
		respRes: &filter.ResultAllowed{
			Rule: allowRule,
		},
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"resp.res-type.adguard-dns.com.", "allowed"},
			{"resp.rule.adguard-dns.com.", allowRule},
			{"resp.rule-list-id.adguard-dns.com.", ""},
		}),
	}, {
		name:    "request_result_modified",
		domain:  dnssvctest.DomainRewrittenFQDN,
		reqInfo: defaultReqInfo,
		reqRes: &filter.ResultModifiedRequest{
			Rule: rewriteRule,
			Msg: dnsservertest.NewReq(
				dnssvctest.DomainRewrittenCNAMEFQDN,
				dns.TypeA,
				dns.ClassINET,
			),
		},
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"req.res-type.adguard-dns.com.", "modified"},
			{"req.rule.adguard-dns.com.", rewriteRule},
			{"req.rule-list-id.adguard-dns.com.", ""},
		}),
	}, {
		name:   "device",
		domain: dnssvctest.DomainFQDN,
		reqInfo: &agd.RequestInfo{
			Messages: agdtest.NewConstructor(),
			Device:   &agd.Device{ID: dnssvctest.DeviceID},
		},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"device-id.adguard-dns.com.", dnssvctest.DeviceIDStr},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name:   "profile",
		domain: dnssvctest.DomainFQDN,
		reqInfo: &agd.RequestInfo{
			Messages: agdtest.NewConstructor(),
			Profile:  &agd.Profile{ID: dnssvctest.ProfileID},
		},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"profile-id.adguard-dns.com.", dnssvctest.ProfileIDStr},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name:   "location",
		domain: dnssvctest.DomainFQDN,
		reqInfo: &agd.RequestInfo{
			Messages: agdtest.NewConstructor(),
			Location: &geoip.Location{Country: geoip.CountryAD},
		},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"country.adguard-dns.com.", string(geoip.CountryAD)},
			{"asn.adguard-dns.com.", "0"},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name:   "location_subdivision",
		domain: dnssvctest.DomainFQDN,
		reqInfo: &agd.RequestInfo{
			Messages: agdtest.NewConstructor(),
			Location: &geoip.Location{Country: geoip.CountryAD, TopSubdivision: "CA"},
		},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"country.adguard-dns.com.", string(geoip.CountryAD)},
			{"asn.adguard-dns.com.", "0"},
			{"subdivision.adguard-dns.com.", "CA"},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(dnssvctest.LocalAddr, dnssvctest.RemoteAddr)

			ctx := agd.ContextWithRequestInfo(context.Background(), tc.reqInfo)

			origReq := dnsservertest.NewReq(tc.domain, dns.TypeA, dns.ClassINET)
			origResp := dnsservertest.NewResp(dns.RcodeSuccess, origReq)

			fctx := &filteringContext{
				originalRequest:  origReq,
				originalResponse: origResp,
				requestResult:    tc.reqRes,
				responseResult:   tc.respRes,
			}

			mw.setFilteredResponse(ctx, fctx, tc.reqInfo)

			err := mw.writeDebugResponse(ctx, fctx, rw)
			require.NoError(t, err)

			msg := rw.Msg()
			require.NotNil(t, msg)

			assert.Equal(t, tc.wantExtra, msg.Extra)
		})
	}
}
