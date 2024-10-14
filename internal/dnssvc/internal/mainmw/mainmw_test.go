package mainmw_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/mainmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common constants for tests.
const (
	testASN     geoip.ASN = 12345
	testCountry           = geoip.CountryAD

	testProto = dnsserver.ProtoDNS

	testRespAddr4Str   = "3.4.5.6"
	testRewriteAddrStr = "7.8.9.0"

	testRuleAllow     agd.FilterRuleText = "@@||" + dnssvctest.DomainAllowed + "^"
	testRuleBlockReq  agd.FilterRuleText = "||" + dnssvctest.DomainBlocked + "^"
	testRuleBlockResp agd.FilterRuleText = "||" + testRespAddr4Str + "^"
	testRuleRewrite   agd.FilterRuleText = "||" + dnssvctest.DomainRewritten +
		"^$dnsrewrite=NOERROR;A;" + testRewriteAddrStr
	testRuleRewriteCNAME agd.FilterRuleText = "||" + dnssvctest.DomainRewritten +
		"^$dnsrewrite=NOERROR;CNAME;" + dnssvctest.DomainRewrittenCNAME
)

// Common variables for tests.
var (
	testRespAddr4   = netip.MustParseAddr(testRespAddr4Str)
	testRespAddr6   = netip.MustParseAddr("3456::789a")
	testRewriteAddr = netip.MustParseAddr(testRewriteAddrStr)

	testDevice = &agd.Device{
		ID: dnssvctest.DeviceID,
	}

	testProfile = &agd.Profile{
		ID:              dnssvctest.ProfileID,
		QueryLogEnabled: true,
		IPLogEnabled:    true,
	}
)

func TestMiddleware_Wrap(t *testing.T) {
	t.Parallel()

	reqStart := time.Now()
	var (
		billStatNotImp = &agdtest.BillStatRecorder{
			OnRecord: func(
				_ context.Context,
				_ agd.DeviceID,
				_ geoip.Country,
				_ geoip.ASN,
				_ time.Time,
				_ agd.Protocol,
			) {
				panic("not implemented")
			},
		}

		billStatCheck = &agdtest.BillStatRecorder{
			OnRecord: func(
				_ context.Context,
				devID agd.DeviceID,
				ctry geoip.Country,
				asn geoip.ASN,
				start time.Time,
				proto agd.Protocol,
			) {
				pt := testutil.PanicT{}
				checkBillStat(pt, devID, ctry, asn, start, proto, reqStart)
			},
		}
	)

	flt := &agdtest.Filter{
		OnFilterRequest: func(
			_ context.Context,
			_ *dns.Msg,
			_ *agd.RequestInfo,
		) (r filter.Result, err error) {
			return nil, nil
		},
		OnFilterResponse: func(
			_ context.Context,
			_ *dns.Msg,
			_ *agd.RequestInfo,
		) (r filter.Result, err error) {
			return nil, nil
		},
	}

	fltStrg := &agdtest.FilterStorage{
		OnFilterFromContext: func(_ context.Context, _ *agd.RequestInfo) (f filter.Interface) {
			return flt
		},
		OnHasListID: func(_ agd.FilterListID) (ok bool) { panic("not implemented") },
	}

	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			_ *geoip.Location,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			panic("not implemented")
		},
		OnData: func(host string, addr netip.Addr) (l *geoip.Location, err error) {
			pt := testutil.PanicT{}
			require.Equal(pt, dnssvctest.Domain, host)
			if addr.Is4() {
				require.Equal(pt, addr, testRespAddr4)
			} else if addr.Is6() {
				require.Equal(pt, addr, testRespAddr6)
			}

			return nil, nil
		},
	}

	ruleStat := &agdtest.RuleStat{
		OnCollect: func(_ context.Context, id agd.FilterListID, text agd.FilterRuleText) {
			pt := testutil.PanicT{}
			require.Equal(pt, agd.FilterListID(""), id)
			require.Equal(pt, agd.FilterRuleText(""), text)
		},
	}

	cloner := agdtest.NewCloner()
	msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              cloner,
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		FilteredResponseTTL: agdtest.FilteredResponseTTL,
	})
	require.NoError(t, err)

	testCases := []struct {
		req        *dns.Msg
		device     *agd.Device
		profile    *agd.Profile
		billStat   *agdtest.BillStatRecorder
		name       string
		wantErrMsg string
	}{{
		req:        dnsservertest.NewReq(dnssvctest.DomainFQDN, dns.TypeA, dns.ClassINET),
		device:     nil,
		profile:    nil,
		billStat:   billStatNotImp,
		name:       "success_ipv4",
		wantErrMsg: "",
	}, {
		req:        dnsservertest.NewReq(dnssvctest.DomainFQDN, dns.TypeAAAA, dns.ClassINET),
		device:     nil,
		profile:    nil,
		billStat:   billStatNotImp,
		name:       "success_ipv6",
		wantErrMsg: "",
	}, {
		req:        dnsservertest.NewReq(dnssvctest.DomainFQDN, dns.TypeA, dns.ClassCHAOS),
		device:     nil,
		profile:    nil,
		billStat:   billStatNotImp,
		name:       "debug",
		wantErrMsg: "",
	}, {
		req:        dnsservertest.NewReq(dnssvctest.DomainFQDN, dns.TypeA, dns.ClassINET),
		device:     testDevice,
		profile:    testProfile,
		billStat:   billStatCheck,
		name:       "success_profile",
		wantErrMsg: "",
	}, {
		req:        dnsservertest.NewReq(dnssvctest.DomainFQDN, dns.TypeAAAA, dns.ClassINET),
		device:     testDevice,
		profile:    testProfile,
		billStat:   billStatCheck,
		name:       "success_ipv6_profile",
		wantErrMsg: "",
	}, {
		req:        dnsservertest.NewReq(dnssvctest.DomainFQDN, dns.TypeA, dns.ClassCHAOS),
		device:     testDevice,
		profile:    testProfile,
		billStat:   billStatCheck,
		name:       "debug_profile",
		wantErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			q := tc.req.Question[0]
			reqFQDN := q.Name
			reqHost := agdnet.NormalizeDomain(reqFQDN)
			reqQType := q.Qtype

			queryLog := &agdtest.QueryLog{
				OnWrite: func(_ context.Context, e *querylog.Entry) (err error) {
					pt := testutil.PanicT{}
					checkQueryLog(pt, e, nil, nil, reqStart, reqFQDN, reqQType)

					return nil
				},
			}

			c := &mainmw.Config{
				Metrics:       mainmw.EmptyMetrics{},
				Messages:      msgs,
				Cloner:        cloner,
				BillStat:      tc.billStat,
				ErrColl:       agdtest.NewErrorCollector(),
				FilterStorage: fltStrg,
				GeoIP:         geoIP,
				QueryLog:      queryLog,
				RuleStat:      ruleStat,
			}

			mw := mainmw.New(c)

			wantResp := dnsservertest.NewResp(dns.RcodeSuccess, tc.req, dnsservertest.SectionAnswer{
				wantAns(t, reqQType),
			})
			h := mw.Wrap(newSimpleHandler(t, tc.req, wantResp))

			ctx := newContext(t, tc.device, tc.profile, reqHost, reqQType, reqStart)
			rw := dnsserver.NewNonWriterResponseWriter(dnssvctest.ServerTCPAddr, dnssvctest.ClientTCPAddr)

			serveErr := h.ServeDNS(ctx, rw, tc.req)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, serveErr)

			assert.Equal(t, wantResp, rw.Msg())
		})
	}
}

// checkBillStat checks the billing statistics call against the common test
// values and given parameters.
func checkBillStat(
	pt testutil.PanicT,
	devID agd.DeviceID,
	ctry geoip.Country,
	asn geoip.ASN,
	start time.Time,
	proto agd.Protocol,
	wantStart time.Time,
) {
	require.Equal(pt, testDevice.ID, devID)
	require.Equal(pt, testCountry, ctry)
	require.Equal(pt, testASN, asn)
	require.Equal(pt, wantStart, start)
	require.Equal(pt, testProto, proto)
}

// checkQueryLog checks the query log entry against the common test values and
// given parameters.
func checkQueryLog(
	pt testutil.PanicT,
	e *querylog.Entry,
	wantReqRes filter.Result,
	wantRespRes filter.Result,
	wantStart time.Time,
	wantFQDN string,
	wantReqType dnsmsg.RRType,
) {
	require.Equal(pt, dnssvctest.ClientAddr, e.RemoteIP)
	require.Equal(pt, wantReqRes, e.RequestResult)
	require.Equal(pt, wantRespRes, e.ResponseResult)
	require.Equal(pt, wantStart, e.Time)
	require.Equal(pt, testDevice.ID, e.DeviceID)
	require.Equal(pt, testProfile.ID, e.ProfileID)
	require.Equal(pt, testCountry, e.ClientCountry)
	require.Equal(pt, wantFQDN, e.DomainFQDN)
	require.Equal(pt, testASN, e.ClientASN)

	// Don't check that e.Elapsed is greater than zero, because most of
	// the time it is zero in the tests.

	require.Equal(pt, wantReqType, e.RequestType)
	require.Equal(pt, testProto, e.Protocol)
	require.False(pt, e.DNSSEC)
	require.Equal(pt, dnsmsg.RCode(dns.RcodeSuccess), e.ResponseCode)
}

// wantAns is a helper that returns the expected address answer based on the
// question type.
func wantAns(t testing.TB, qtype dnsmsg.RRType) (ans dns.RR) {
	t.Helper()

	const fqdn = dnssvctest.DomainFQDN
	switch qtype {
	case dns.TypeA:
		return dnsservertest.NewA(fqdn, agdtest.FilteredResponseTTLSec, testRespAddr4)
	case dns.TypeAAAA:
		return dnsservertest.NewAAAA(fqdn, agdtest.FilteredResponseTTLSec, testRespAddr6)
	default:
		t.Fatalf("bad qtype: %v", qtype)

		// Never reached.
		return nil
	}
}

// newContext returns a new context with the given data, the common test values
// for location and protocol, as well as an enabled filtering-group with the
// standard list IDs.
func newContext(
	tb testing.TB,
	d *agd.Device,
	p *agd.Profile,
	host string,
	qType dnsmsg.RRType,
	start time.Time,
) (ctx context.Context) {
	tb.Helper()

	ctx = context.Background()
	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
		StartTime: start,
	})
	ctx = agd.ContextWithRequestInfo(ctx, &agd.RequestInfo{
		DeviceResult: &agd.DeviceResultOK{
			Device:  d,
			Profile: p,
		},
		Location: &geoip.Location{
			Country: testCountry,
			ASN:     testASN,
		},
		FilteringGroup: &agd.FilteringGroup{
			RuleListIDs: []agd.FilterListID{
				dnssvctest.FilterListID1,
				dnssvctest.FilterListID2,
			},
			RuleListsEnabled: true,
		},
		Messages: agdtest.NewConstructor(tb),
		RemoteIP: dnssvctest.ClientAddr,
		Host:     host,
		QType:    qType,
		Proto:    testProto,
	})

	return ctx
}

// newSimpleHandler returns a simple handler that checks whether a request is
// performed correctly and returns the given response.
func newSimpleHandler(t testing.TB, wantReq, resp *dns.Msg) (h dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		require.Equal(t, wantReq, req)

		return rw.WriteMsg(ctx, req, resp)
	}

	return dnsserver.HandlerFunc(f)
}

func TestMiddleware_Wrap_filtering(t *testing.T) {
	t.Parallel()

	reqStart := time.Now()
	var (
		billStatNotImp = &agdtest.BillStatRecorder{
			OnRecord: func(
				_ context.Context,
				_ agd.DeviceID,
				_ geoip.Country,
				_ geoip.ASN,
				_ time.Time,
				_ agd.Protocol,
			) {
				panic("not implemented")
			},
		}

		billStatCheck = &agdtest.BillStatRecorder{
			OnRecord: func(
				_ context.Context,
				devID agd.DeviceID,
				ctry geoip.Country,
				asn geoip.ASN,
				start time.Time,
				proto agd.Protocol,
			) {
				pt := testutil.PanicT{}
				checkBillStat(pt, devID, ctry, asn, start, proto, reqStart)
			},
		}
	)

	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			_ *geoip.Location,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			panic("not implemented")
		},
		OnData: func(host string, addr netip.Addr) (l *geoip.Location, err error) {
			return nil, nil
		},
	}

	var (
		reqAllow = dnsservertest.NewReq(
			dnssvctest.DomainAllowedFQDN,
			dns.TypeA,
			dns.ClassINET,
		)

		reqBlock = dnsservertest.NewReq(
			dnssvctest.DomainBlockedFQDN,
			dns.TypeA,
			dns.ClassINET,
		)

		reqRewrite = dnsservertest.NewReq(
			dnssvctest.DomainRewrittenFQDN,
			dns.TypeA,
			dns.ClassINET,
		)

		reqRewriteCNAME = dnsservertest.NewReq(
			dnssvctest.DomainRewrittenCNAMEFQDN,
			dns.TypeA,
			dns.ClassINET,
		)
	)

	var (
		respAllow = dnsservertest.NewResp(dns.RcodeSuccess, reqAllow, dnsservertest.SectionAnswer{
			wantAns(t, dns.TypeA),
		})

		respBlock = dnsservertest.NewResp(dns.RcodeSuccess, reqBlock, dnsservertest.SectionAnswer{
			dnsservertest.NewA(
				dnssvctest.DomainBlockedFQDN,
				agdtest.FilteredResponseTTLSec,
				netip.IPv4Unspecified(),
			),
		})

		respRewrite = dnsservertest.NewResp(
			dns.RcodeSuccess,
			reqRewrite,
			dnsservertest.SectionAnswer{
				dnsservertest.NewA(
					dnssvctest.DomainRewrittenFQDN,
					agdtest.FilteredResponseTTLSec,
					testRewriteAddr,
				),
			},
		)

		respRewriteCNAMEUps = dnsservertest.NewResp(
			dns.RcodeSuccess,
			reqRewrite,
			dnsservertest.SectionAnswer{
				dnsservertest.NewA(
					dnssvctest.DomainRewrittenCNAMEFQDN,
					agdtest.FilteredResponseTTLSec,
					testRewriteAddr,
				),
			},
		)

		respRewriteCNAME = dnsservertest.NewResp(
			dns.RcodeSuccess,
			reqRewrite,
			dnsservertest.SectionAnswer{
				dnsservertest.NewCNAME(
					dnssvctest.DomainRewrittenFQDN,
					agdtest.FilteredResponseTTLSec,
					dnssvctest.DomainRewrittenCNAMEFQDN,
				),
				dnsservertest.NewA(
					dnssvctest.DomainRewrittenCNAMEFQDN,
					agdtest.FilteredResponseTTLSec,
					testRewriteAddr,
				),
			},
		)
	)

	var (
		resReqAllow = &filter.ResultAllowed{
			List: dnssvctest.FilterListID1,
			Rule: testRuleAllow,
		}

		resReqBlock = &filter.ResultBlocked{
			List: dnssvctest.FilterListID1,
			Rule: testRuleBlockReq,
		}

		resReqRewrite = &filter.ResultModifiedResponse{
			List: dnssvctest.FilterListID1,
			Rule: testRuleRewrite,
			Msg:  respRewrite,
		}

		resReqRewriteCNAME = &filter.ResultModifiedRequest{
			List: dnssvctest.FilterListID1,
			Rule: testRuleRewriteCNAME,
			Msg:  reqRewriteCNAME,
		}

		resRespBlock = &filter.ResultBlocked{
			List: dnssvctest.FilterListID1,
			Rule: testRuleBlockResp,
		}
	)

	cloner := agdtest.NewCloner()
	msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              cloner,
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		FilteredResponseTTL: agdtest.FilteredResponseTTL,
	})
	require.NoError(t, err)

	testCases := []struct {
		req        *dns.Msg
		device     *agd.Device
		profile    *agd.Profile
		billStat   *agdtest.BillStatRecorder
		wantResp   *dns.Msg
		wantUpsReq *dns.Msg
		upsResp    *dns.Msg
		reqRes     filter.Result
		respRes    filter.Result
		name       string
		wantErrMsg string
		wantRule   agd.FilterRuleText
	}{{
		req:        reqAllow,
		device:     nil,
		profile:    nil,
		billStat:   billStatNotImp,
		reqRes:     resReqAllow,
		respRes:    nil,
		wantResp:   respAllow,
		wantUpsReq: reqAllow,
		upsResp:    respAllow,
		name:       "success_allowed",
		wantErrMsg: "",
		wantRule:   testRuleAllow,
	}, {
		req:        reqBlock,
		device:     nil,
		profile:    nil,
		billStat:   billStatNotImp,
		reqRes:     resReqBlock,
		respRes:    nil,
		wantResp:   respBlock,
		wantUpsReq: reqBlock,
		upsResp:    respAllow,
		name:       "success_blocked",
		wantErrMsg: "",
		wantRule:   testRuleBlockReq,
	}, {
		req:        reqRewrite,
		device:     nil,
		profile:    nil,
		billStat:   billStatNotImp,
		reqRes:     resReqRewriteCNAME,
		respRes:    nil,
		wantResp:   respRewriteCNAME,
		wantUpsReq: reqRewriteCNAME,
		upsResp:    respRewriteCNAMEUps,
		name:       "success_rewritten_req",
		wantErrMsg: "",
		wantRule:   testRuleRewriteCNAME,
	}, {
		req:        reqRewrite,
		device:     nil,
		profile:    nil,
		billStat:   billStatNotImp,
		reqRes:     resReqRewrite,
		respRes:    nil,
		wantResp:   respRewrite,
		wantUpsReq: reqRewrite,
		upsResp:    respAllow,
		name:       "success_rewritten_resp",
		wantErrMsg: "",
		wantRule:   testRuleRewrite,
	}, {
		req:        reqAllow,
		device:     testDevice,
		profile:    testProfile,
		billStat:   billStatCheck,
		reqRes:     resReqAllow,
		respRes:    nil,
		wantResp:   respAllow,
		wantUpsReq: reqAllow,
		upsResp:    respAllow,
		name:       "success_profile_allowed",
		wantErrMsg: "",
		wantRule:   testRuleAllow,
	}, {
		req:        reqBlock,
		device:     testDevice,
		profile:    testProfile,
		billStat:   billStatCheck,
		reqRes:     resReqBlock,
		respRes:    nil,
		wantResp:   respBlock,
		wantUpsReq: reqBlock,
		upsResp:    respAllow,
		name:       "success_profile_blocked",
		wantErrMsg: "",
		wantRule:   testRuleBlockReq,
	}, {
		req:        reqBlock,
		device:     nil,
		profile:    nil,
		billStat:   billStatNotImp,
		reqRes:     nil,
		respRes:    resRespBlock,
		wantResp:   respBlock,
		wantUpsReq: reqBlock,
		upsResp:    respAllow,
		name:       "success_blocked_resp",
		wantErrMsg: "",
		wantRule:   testRuleBlockResp,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			flt := &agdtest.Filter{
				OnFilterRequest: func(
					_ context.Context,
					_ *dns.Msg,
					_ *agd.RequestInfo,
				) (r filter.Result, err error) {
					return tc.reqRes, nil
				},
				OnFilterResponse: func(
					_ context.Context,
					_ *dns.Msg,
					_ *agd.RequestInfo,
				) (r filter.Result, err error) {
					return tc.respRes, nil
				},
			}

			fltStrg := &agdtest.FilterStorage{
				OnFilterFromContext: func(
					_ context.Context,
					_ *agd.RequestInfo,
				) (f filter.Interface) {
					return flt
				},
				OnHasListID: func(_ agd.FilterListID) (ok bool) { panic("not implemented") },
			}

			q := tc.req.Question[0]
			reqFQDN := q.Name
			reqHost := agdnet.NormalizeDomain(reqFQDN)
			reqQType := q.Qtype

			queryLog := &agdtest.QueryLog{
				OnWrite: func(_ context.Context, e *querylog.Entry) (err error) {
					pt := testutil.PanicT{}
					checkQueryLog(pt, e, tc.reqRes, tc.respRes, reqStart, reqFQDN, reqQType)

					return nil
				},
			}

			ruleStat := &agdtest.RuleStat{
				OnCollect: func(_ context.Context, id agd.FilterListID, text agd.FilterRuleText) {
					pt := testutil.PanicT{}
					require.Equal(pt, dnssvctest.FilterListID1, id)
					require.Equal(pt, tc.wantRule, text)
				},
			}

			c := &mainmw.Config{
				Metrics:       mainmw.EmptyMetrics{},
				Messages:      msgs,
				Cloner:        cloner,
				BillStat:      tc.billStat,
				ErrColl:       agdtest.NewErrorCollector(),
				FilterStorage: fltStrg,
				GeoIP:         geoIP,
				QueryLog:      queryLog,
				RuleStat:      ruleStat,
			}

			mw := mainmw.New(c)

			h := mw.Wrap(newSimpleHandler(t, tc.wantUpsReq, tc.upsResp))

			ctx := newContext(t, tc.device, tc.profile, reqHost, reqQType, reqStart)
			rw := dnsserver.NewNonWriterResponseWriter(dnssvctest.ServerTCPAddr, dnssvctest.ClientTCPAddr)

			serveErr := h.ServeDNS(ctx, rw, tc.req)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, serveErr)

			assert.Equal(t, tc.wantResp, rw.Msg())
		})
	}
}
