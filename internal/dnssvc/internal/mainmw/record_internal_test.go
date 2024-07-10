package mainmw

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_recordQueryInfo_respCtry(t *testing.T) {
	t.Parallel()

	const (
		fqdn   = dnssvctest.DomainFQDN
		class  = dns.ClassINET
		ttlSec = 10

		testCtry = geoip.CountryAD
	)

	var (
		reqA     = dnsservertest.NewReq(fqdn, dns.TypeA, class)
		reqAAAA  = dnsservertest.NewReq(fqdn, dns.TypeAAAA, class)
		reqTXT   = dnsservertest.NewReq(fqdn, dns.TypeTXT, class)
		reqHTTPS = dnsservertest.NewReq(fqdn, dns.TypeHTTPS, class)
	)

	testCases := []struct {
		req          *dns.Msg
		name         string
		wantRespCtry geoip.Country
		respAns      []dns.RR
		respRCode    dnsmsg.RCode
		wantGeoIP    bool
	}{{
		req:          reqA,
		name:         "empty",
		wantRespCtry: geoip.CountryNotApplicable,
		respAns:      nil,
		respRCode:    dns.RcodeSuccess,
		wantGeoIP:    false,
	}, {
		req:          reqA,
		name:         "refused",
		wantRespCtry: geoip.CountryNotApplicable,
		respAns:      nil,
		respRCode:    dns.RcodeRefused,
		wantGeoIP:    false,
	}, {
		req:          reqA,
		name:         "a",
		wantRespCtry: testCtry,
		respAns: []dns.RR{
			dnsservertest.NewA(fqdn, ttlSec, dnssvctest.DomainAddrIPv4),
		},
		respRCode: dns.RcodeSuccess,
		wantGeoIP: true,
	}, {
		req:          reqA,
		name:         "a_unspec",
		wantRespCtry: geoip.CountryNotApplicable,
		respAns: []dns.RR{
			dnsservertest.NewA(fqdn, ttlSec, netip.IPv4Unspecified()),
		},
		respRCode: dns.RcodeSuccess,
		wantGeoIP: false,
	}, {
		req:          reqAAAA,
		name:         "aaaa",
		wantRespCtry: testCtry,
		respAns: []dns.RR{
			dnsservertest.NewAAAA(fqdn, ttlSec, dnssvctest.DomainAddrIPv6),
		},
		respRCode: dns.RcodeSuccess,
		wantGeoIP: true,
	}, {
		req:          reqTXT,
		name:         "txt",
		wantRespCtry: geoip.CountryNotApplicable,
		respAns: []dns.RR{
			dnsservertest.NewTXT(fqdn, ttlSec),
		},
		respRCode: dns.RcodeSuccess,
		wantGeoIP: false,
	}, {
		req:          reqHTTPS,
		name:         "https_no_ips",
		wantRespCtry: geoip.CountryNotApplicable,
		respAns: []dns.RR{
			dnsservertest.NewHTTPS(fqdn, ttlSec, nil, nil),
		},
		respRCode: dns.RcodeSuccess,
		wantGeoIP: false,
	}, {
		req:          reqHTTPS,
		name:         "https_ipv4",
		wantRespCtry: testCtry,
		respAns: []dns.RR{
			dnsservertest.NewHTTPS(fqdn, ttlSec, []netip.Addr{dnssvctest.DomainAddrIPv4}, nil),
		},
		respRCode: dns.RcodeSuccess,
		wantGeoIP: true,
	}, {
		req:          reqHTTPS,
		name:         "https_ipv6",
		wantRespCtry: testCtry,
		respAns: []dns.RR{
			dnsservertest.NewHTTPS(fqdn, ttlSec, nil, []netip.Addr{dnssvctest.DomainAddrIPv6}),
		},
		respRCode: dns.RcodeSuccess,
		wantGeoIP: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			loc := &geoip.Location{
				Country: testCtry,
			}

			geoIP := &agdtest.GeoIP{
				OnSubnetByLocation: func(
					_ *geoip.Location,
					_ netutil.AddrFamily,
				) (n netip.Prefix, err error) {
					panic("not implemented")
				},
				OnData: func(_ string, _ netip.Addr) (l *geoip.Location, err error) {
					if !tc.wantGeoIP {
						t.Error("unexpected call to geoip")
					}

					return loc, nil
				},
			}

			queryLogCalled := false
			var gotRespCtry geoip.Country
			queryLog := &agdtest.QueryLog{
				OnWrite: func(_ context.Context, e *querylog.Entry) (err error) {
					queryLogCalled = true

					require.NotNil(t, e)
					gotRespCtry = e.ResponseCountry

					return nil
				},
			}

			mw := &Middleware{
				billStat: billstat.EmptyRecorder{},
				geoIP:    geoIP,
				queryLog: queryLog,
				ruleStat: rulestat.Empty{},
			}

			ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{
				StartTime: time.Now(),
			})

			fctx := &filteringContext{
				originalRequest: tc.req,
				filteredResponse: dnsservertest.NewResp(
					int(tc.respRCode),
					tc.req,
					dnsservertest.SectionAnswer(tc.respAns),
				),
			}

			ri := &agd.RequestInfo{
				Profile: &agd.Profile{
					QueryLogEnabled: true,
				},
				Device: &agd.Device{},
				QType:  tc.req.Question[0].Qtype,
				QClass: class,
			}

			mw.recordQueryInfo(ctx, fctx, ri)
			require.True(t, queryLogCalled)

			assert.Equal(t, gotRespCtry, tc.wantRespCtry)
		})
	}
}
