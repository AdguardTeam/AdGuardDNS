package mainmw

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
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
	cloner := agdtest.NewCloner()
	msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              cloner,
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		StructuredErrors:    agdtest.NewSDEConfig(true),
		FilteredResponseTTL: agdtest.FilteredResponseTTL,
		EDEEnabled:          true,
	})
	require.NoError(t, err)

	// TODO(a.garipov): Consider moving to dnssvctest and DRY'ing with
	// mainmw_test.
	const (
		allowRule   = "||" + dnssvctest.DomainAllowed + "^"
		blockRule   = "||" + dnssvctest.DomainBlocked + "^"
		rewriteRule = "||" + dnssvctest.DomainRewritten + "^$dnsrewrite=REFUSED"

		nodeName = "test-node"
	)

	mw := &Middleware{
		messages: msgs,
		cloner:   cloner,
		errColl:  agdtest.NewErrorCollector(),
		nodeName: nodeName,
	}

	clientIPStr := dnssvctest.ClientIP.String()
	serverIPStr := dnssvctest.ServerAddr.String()

	defaultReqInfo := &agd.RequestInfo{
		Messages: msgs,
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
			{"node-name.adguard-dns.com.", nodeName},
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
			{"node-name.adguard-dns.com.", nodeName},
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
			{"node-name.adguard-dns.com.", nodeName},
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
			{"node-name.adguard-dns.com.", nodeName},
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
			{"node-name.adguard-dns.com.", nodeName},
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
			{"node-name.adguard-dns.com.", nodeName},
			{"req.res-type.adguard-dns.com.", "modified"},
			{"req.rule.adguard-dns.com.", rewriteRule},
			{"req.rule-list-id.adguard-dns.com.", ""},
		}),
	}, {
		name:   "device",
		domain: dnssvctest.DomainFQDN,
		reqInfo: &agd.RequestInfo{
			DeviceResult: &agd.DeviceResultOK{
				Device:  &agd.Device{ID: dnssvctest.DeviceID},
				Profile: &agd.Profile{ID: dnssvctest.ProfileID},
			},
			Messages: agdtest.NewConstructor(t),
		},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"node-name.adguard-dns.com.", nodeName},
			{"device-id.adguard-dns.com.", dnssvctest.DeviceIDStr},
			{"profile-id.adguard-dns.com.", dnssvctest.ProfileIDStr},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name:   "location",
		domain: dnssvctest.DomainFQDN,
		reqInfo: &agd.RequestInfo{
			Messages: agdtest.NewConstructor(t),
			Location: &geoip.Location{Country: geoip.CountryAD},
		},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"node-name.adguard-dns.com.", nodeName},
			{"country.adguard-dns.com.", string(geoip.CountryAD)},
			{"asn.adguard-dns.com.", "0"},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name:   "location_subdivision",
		domain: dnssvctest.DomainFQDN,
		reqInfo: &agd.RequestInfo{
			Messages: agdtest.NewConstructor(t),
			Location: &geoip.Location{Country: geoip.CountryAD, TopSubdivision: "CA"},
		},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", clientIPStr},
			{"server-ip.adguard-dns.com.", serverIPStr},
			{"node-name.adguard-dns.com.", nodeName},
			{"country.adguard-dns.com.", string(geoip.CountryAD)},
			{"asn.adguard-dns.com.", "0"},
			{"subdivision.adguard-dns.com.", "CA"},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(
				dnssvctest.ServerTCPAddr,
				dnssvctest.ClientTCPAddr,
			)

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

			writeErr := mw.writeDebugResponse(ctx, fctx, rw)
			require.NoError(t, writeErr)

			msg := rw.Msg()
			require.NotNil(t, msg)

			assert.Equal(t, tc.wantExtra, msg.Extra)
		})
	}
}
