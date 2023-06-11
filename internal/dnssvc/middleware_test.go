package dnssvc_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testProfID is the [agd.ProfileID] for tests.
	testProfID agd.ProfileID = "prof1234"

	// testDevID is the [agd.DeviceID] for tests.
	testDevID agd.DeviceID = "dev1234"

	// testFltListID is the [agd.FilterListID] for tests.
	testFltListID agd.FilterListID = "flt1234"

	// testSrvName is the [agd.ServerName] for tests.
	testSrvName agd.ServerName = "test_server_dns_tls"

	// testSrvGrpName is the [agd.ServerGroupName] for tests.
	testSrvGrpName agd.ServerGroupName = "test_group"

	// testDevIDWildcard is the wildcard domain for retrieving [agd.DeviceID] in
	// tests.  Use [strings.ReplaceAll] to replace the "*" symbol with the
	// actual [agd.DeviceID].
	testDevIDWildcard string = "*.dns.example.com"
)

// testTimeout is the common timeout for tests.
const testTimeout time.Duration = 1 * time.Second

// newTestService creates a new [dnssvc.Service] for tests.  The service built
// of stubs, that use the following data:
//
//   - A filtering group containing a filter with [testFltListID] and enabled
//     rule lists.
//   - A device with [testDevID] and enabled filtering.
//   - A profile with [testProfID] with enabled filtering and query
//     logging, containing the device.
//   - GeoIP database always returning [agd.CountryAD], [agd.ContinentEU], and
//     ASN of 42.
//   - A server with [testSrvName] under group with [testSrvGrpName], matching
//     the DeviceID with [testDevIDWildcard].
//
// Each stub also uses the corresponding channels to send the data it receives
// from the service.  If the channel is [nil], the stub ignores it.  Each
// sending to a channel wrapped with [testutil.RequireSend] using [testTimeout].
//
// It also uses the [dnsservertest.DefaultHandler] to create the DNS handler.
func newTestService(
	t testing.TB,
	flt filter.Interface,
	errCollCh chan<- error,
	profileDBCh chan<- agd.DeviceID,
	querylogCh chan<- *querylog.Entry,
	geoIPCh chan<- string,
	dnsDBCh chan<- *agd.RequestInfo,
	ruleStatCh chan<- agd.FilterRuleText,
) (svc *dnssvc.Service, srvAddr netip.AddrPort) {
	t.Helper()

	pt := testutil.PanicT{}

	dev := &agd.Device{
		ID:               testDevID,
		FilteringEnabled: true,
	}

	prof := &agd.Profile{
		ID:                  testProfID,
		DeviceIDs:           []agd.DeviceID{testDevID},
		RuleListIDs:         []agd.FilterListID{testFltListID},
		FilteredResponseTTL: agdtest.FilteredResponseTTL,
		FilteringEnabled:    true,
		QueryLogEnabled:     true,
	}

	db := &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			id agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			if profileDBCh != nil {
				testutil.RequireSend(pt, profileDBCh, id, testTimeout)
			}

			return prof, dev, nil
		},
		OnProfileByDedicatedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
		OnProfileByLinkedIP: func(
			ctx context.Context,
			ip netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
	}

	// Make sure that any panics and errors within handlers are caught and
	// that they fail the test by panicking.
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			if errCollCh != nil {
				testutil.RequireSend(pt, errCollCh, err, testTimeout)
			}
		},
	}

	loc := &agd.Location{
		Country:   agd.CountryAD,
		Continent: agd.ContinentEU,
		ASN:       42,
	}
	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			_ agd.Country,
			_ agd.ASN,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			panic("not implemented")
		},
		OnData: func(host string, _ netip.Addr) (l *agd.Location, err error) {
			if geoIPCh != nil {
				testutil.RequireSend(pt, geoIPCh, host, testTimeout)
			}

			return loc, nil
		},
	}

	fltStrg := &agdtest.FilterStorage{
		OnFilterFromContext: func(_ context.Context, _ *agd.RequestInfo) (f filter.Interface) {
			return flt
		},
		OnHasListID: func(_ agd.FilterListID) (ok bool) { panic("not implemented") },
	}

	var ql querylog.Interface = &agdtest.QueryLog{
		OnWrite: func(_ context.Context, e *querylog.Entry) (err error) {
			if querylogCh != nil {
				testutil.RequireSend(pt, querylogCh, e, testTimeout)
			}

			return nil
		},
	}

	srvAddr = netip.MustParseAddrPort("94.149.14.14:853")
	srvs := []*agd.Server{{
		DNSCrypt: nil,
		TLS:      nil,
		Name:     testSrvName,
		BindData: []*agd.ServerBindData{{
			AddrPort: srvAddr,
		}},
		Protocol: agd.ProtoDoT,
	}}

	tl := newTestListener()
	tl.onStart = func(_ context.Context) (err error) { return nil }
	tl.onShutdown = func(_ context.Context) (err error) { return nil }

	dnsCk := &agdtest.DNSCheck{
		OnCheck: func(
			_ context.Context,
			_ *dns.Msg,
			_ *agd.RequestInfo,
		) (resp *dns.Msg, err error) {
			return nil, nil
		},
	}

	dnsDB := &agdtest.DNSDB{
		OnRecord: func(_ context.Context, _ *dns.Msg, ri *agd.RequestInfo) {
			if dnsDBCh != nil {
				testutil.RequireSend(pt, dnsDBCh, ri, testTimeout)
			}
		},
	}

	ruleStat := &agdtest.RuleStat{
		OnCollect: func(_ context.Context, _ agd.FilterListID, text agd.FilterRuleText) {
			if ruleStatCh != nil {
				testutil.RequireSend(pt, ruleStatCh, text, testTimeout)
			}
		},
	}

	rl := &agdtest.RateLimit{
		OnIsRateLimited: func(
			_ context.Context,
			_ *dns.Msg,
			_ netip.Addr,
		) (drop, allowlisted bool, err error) {
			return true, false, nil
		},
		OnCountResponses: func(_ context.Context, _ *dns.Msg, _ netip.Addr) {
			panic("not implemented")
		},
	}

	testFltGrpID := agd.FilteringGroupID("1234")

	c := &dnssvc.Config{
		Messages: agdtest.NewConstructor(),
		BillStat: &agdtest.BillStatRecorder{
			OnRecord: func(
				_ context.Context,
				_ agd.DeviceID,
				_ agd.Country,
				_ agd.ASN,
				_ time.Time,
				_ agd.Protocol,
			) {
			},
		},
		ProfileDB:     db,
		DNSCheck:      dnsCk,
		NonDNS:        http.NotFoundHandler(),
		DNSDB:         dnsDB,
		ErrColl:       errColl,
		FilterStorage: fltStrg,
		GeoIP:         geoIP,
		QueryLog:      ql,
		RuleStat:      ruleStat,
		NewListener:   newTestListenerFunc(tl),
		Handler:       dnsservertest.DefaultHandler(),
		RateLimit:     rl,
		FilteringGroups: map[agd.FilteringGroupID]*agd.FilteringGroup{
			testFltGrpID: {
				ID:               testFltGrpID,
				RuleListIDs:      []agd.FilterListID{testFltListID},
				RuleListsEnabled: true,
			},
		},
		ServerGroups: []*agd.ServerGroup{{
			TLS: &agd.TLS{
				DeviceIDWildcards: []string{testDevIDWildcard},
			},
			DDR: &agd.DDR{
				Enabled: true,
			},
			Name:           testSrvGrpName,
			FilteringGroup: testFltGrpID,
			Servers:        srvs,
		}},
	}

	svc, err := dnssvc.New(c)
	require.NoError(t, err)
	require.NotNil(t, svc)

	err = svc.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(context.Background())
	})

	return svc, srvAddr
}

func TestService_Wrap(t *testing.T) {
	profileDBCh := make(chan agd.DeviceID, 1)
	querylogCh := make(chan *querylog.Entry, 1)
	geoIPCh := make(chan string, 2)
	dnsDBCh := make(chan *agd.RequestInfo, 1)
	ruleStatCh := make(chan agd.FilterRuleText, 1)

	errCollCh := make(chan error, 1)
	go func() {
		for err := range errCollCh {
			require.NoError(t, err)
		}
	}()

	const domain = "example.org"

	domainFQDN := dns.Fqdn(domain)

	reqType := dns.TypeA
	req := dnsservertest.CreateMessage(domain, reqType)

	clientAddr := &net.TCPAddr{IP: net.IP{1, 2, 3, 4}, Port: 12345}

	ctx := context.Background()
	ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
		TLSServerName: strings.ReplaceAll(testDevIDWildcard, "*", string(testDevID)),
	})
	ctx = dnsserver.ContextWithServerInfo(ctx, dnsserver.ServerInfo{
		Proto: agd.ProtoDoT,
	})

	t.Run("simple_success", func(t *testing.T) {
		noMatch := func(
			_ context.Context,
			m *dns.Msg,
			_ *agd.RequestInfo,
		) (r filter.Result, err error) {
			pt := testutil.PanicT{}
			require.NotEmpty(pt, m.Question)
			require.Equal(pt, domainFQDN, m.Question[0].Name)

			return nil, nil
		}

		flt := &agdtest.Filter{
			OnFilterRequest:  noMatch,
			OnFilterResponse: noMatch,
		}

		svc, srvAddr := newTestService(
			t,
			flt,
			errCollCh,
			profileDBCh,
			querylogCh,
			geoIPCh,
			dnsDBCh,
			ruleStatCh,
		)

		rw := dnsserver.NewNonWriterResponseWriter(
			net.TCPAddrFromAddrPort(srvAddr),
			clientAddr,
		)

		ctx = dnsserver.ContextWithStartTime(ctx, time.Now())

		err := svc.Handle(ctx, testSrvGrpName, testSrvName, rw, req)
		require.NoError(t, err)

		resp := rw.Msg()
		dnsservertest.RequireResponse(t, req, resp, 1, dns.RcodeSuccess, false)

		assert.Equal(t, testDevID, <-profileDBCh)

		logEntry := <-querylogCh
		assert.Equal(t, domainFQDN, logEntry.DomainFQDN)
		assert.Equal(t, reqType, logEntry.RequestType)

		assert.Equal(t, "", <-geoIPCh)
		assert.Equal(t, domain, <-geoIPCh)

		dnsDBReqInfo := <-dnsDBCh
		assert.NotNil(t, dnsDBReqInfo)
		assert.Equal(t, agd.FilterRuleText(""), <-ruleStatCh)
	})

	t.Run("request_cname", func(t *testing.T) {
		const (
			cname                        = "cname.example.org"
			cnameRule agd.FilterRuleText = "||" + domain + "^$dnsrewrite=" + cname
		)

		cnameFQDN := dns.Fqdn(cname)

		flt := &agdtest.Filter{
			OnFilterRequest: func(
				_ context.Context,
				m *dns.Msg,
				_ *agd.RequestInfo,
			) (r filter.Result, err error) {
				// Pretend a CNAME rewrite matched the request.
				mod := dnsmsg.Clone(m)
				mod.Question[0].Name = cnameFQDN

				return &filter.ResultModified{
					Msg:  mod,
					List: testFltListID,
					Rule: cnameRule,
				}, nil
			},
			OnFilterResponse: func(
				_ context.Context,
				_ *dns.Msg,
				_ *agd.RequestInfo,
			) (filter.Result, error) {
				panic("not implemented")
			},
		}

		svc, srvAddr := newTestService(
			t,
			flt,
			errCollCh,
			profileDBCh,
			querylogCh,
			geoIPCh,
			dnsDBCh,
			ruleStatCh,
		)

		rw := dnsserver.NewNonWriterResponseWriter(
			net.TCPAddrFromAddrPort(srvAddr),
			clientAddr,
		)

		ctx = dnsserver.ContextWithStartTime(ctx, time.Now())

		err := svc.Handle(ctx, testSrvGrpName, testSrvName, rw, req)
		require.NoError(t, err)

		resp := rw.Msg()
		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 2)

		assert.Equal(t, []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   domainFQDN,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    uint32(agdtest.FilteredResponseTTL.Seconds()),
			},
			Target: cnameFQDN,
		}, &dns.A{
			Hdr: dns.RR_Header{
				Name:   cnameFQDN,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(dnsservertest.AnswerTTL.Seconds()),
			},
			A: netutil.IPv4Localhost().AsSlice(),
		}}, resp.Answer)

		assert.Equal(t, testDevID, <-profileDBCh)

		logEntry := <-querylogCh
		assert.Equal(t, domainFQDN, logEntry.DomainFQDN)
		assert.Equal(t, reqType, logEntry.RequestType)

		assert.Equal(t, "", <-geoIPCh)
		assert.Equal(t, cname, <-geoIPCh)

		dnsDBReqInfo := <-dnsDBCh
		assert.Equal(t, cname, dnsDBReqInfo.Host)
		assert.Equal(t, cnameRule, <-ruleStatCh)
	})
}
