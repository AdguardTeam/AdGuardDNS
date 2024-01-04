package dnssvc_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestService creates a new [dnssvc.Service] for tests.  The service built
// of stubs, that use the following data:
//
//   - A filtering group containing a filter with [dnssvctest.FilterListID1] and
//     enabled rule lists.
//   - A device with [dnssvctest.DeviceID] and enabled filtering.
//   - A profile with [dnssvctest.ProfileID] with enabled filtering and query
//     logging, containing the device.
//   - GeoIP database always returning [agd.CountryAD], [agd.ContinentEU], and
//     ASN of 42.
//   - A server with [testSrvName] under group with [testSrvGrpName], matching
//     the DeviceID with [dnssvctest.DeviceIDWildcard].
//
// Each stub also uses the corresponding channels to send the data it receives
// from the service.  The channels must not be nil.  Each sending to a channel
// wrapped with [testutil.RequireSend] using [dnssvctest.Timeout].
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
		ID:               dnssvctest.DeviceID,
		FilteringEnabled: true,
	}

	prof := &agd.Profile{
		Access:              access.EmptyProfile{},
		ID:                  dnssvctest.ProfileID,
		DeviceIDs:           []agd.DeviceID{dnssvctest.DeviceID},
		RuleListIDs:         []agd.FilterListID{dnssvctest.FilterListID1},
		FilteredResponseTTL: agdtest.FilteredResponseTTL,
		FilteringEnabled:    true,
		QueryLogEnabled:     true,
	}

	db := &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			id agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			testutil.RequireSend(pt, profileDBCh, id, dnssvctest.Timeout)

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

	accessManager := &agdtest.AccessManager{
		OnIsBlockedHost: func(host string, qt uint16) (blocked bool) {
			return false
		},
		OnIsBlockedIP: func(ip netip.Addr) (blocked bool, rule string) {
			return false, ""
		},
	}

	// Make sure that any panics and errors within handlers are caught and
	// that they fail the test by panicking.
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			testutil.RequireSend(pt, errCollCh, err, dnssvctest.Timeout)
		},
	}

	loc := &geoip.Location{
		Country:   geoip.CountryAD,
		Continent: geoip.ContinentEU,
		ASN:       42,
	}
	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			_ *geoip.Location,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			panic("not implemented")
		},
		OnData: func(host string, _ netip.Addr) (l *geoip.Location, err error) {
			testutil.RequireSend(pt, geoIPCh, host, dnssvctest.Timeout)

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
			testutil.RequireSend(pt, querylogCh, e, dnssvctest.Timeout)

			return nil
		},
	}

	srvAddr = netip.MustParseAddrPort("94.149.14.14:853")
	srv := dnssvctest.NewServer(dnssvctest.ServerName, agd.ProtoDoT, &agd.ServerBindData{
		AddrPort: srvAddr,
	})

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
			testutil.RequireSend(pt, dnsDBCh, ri, dnssvctest.Timeout)
		},
	}

	ruleStat := &agdtest.RuleStat{
		OnCollect: func(_ context.Context, _ agd.FilterListID, text agd.FilterRuleText) {
			testutil.RequireSend(pt, ruleStatCh, text, dnssvctest.Timeout)
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
		AccessManager: accessManager,
		Messages:      agdtest.NewConstructor(),
		BillStat: &agdtest.BillStatRecorder{
			OnRecord: func(
				_ context.Context,
				_ agd.DeviceID,
				_ geoip.Country,
				_ geoip.ASN,
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
				RuleListIDs:      []agd.FilterListID{dnssvctest.FilterListID1},
				RuleListsEnabled: true,
			},
		},
		ServerGroups: []*agd.ServerGroup{{
			TLS: &agd.TLS{
				DeviceIDWildcards: []string{dnssvctest.DeviceIDWildcard},
			},
			DDR: &agd.DDR{
				Enabled: true,
			},
			Name:           testSrvGrpName,
			FilteringGroup: testFltGrpID,
			Servers:        []*agd.Server{srv},
		}},
	}

	svc, err := dnssvc.New(c)
	require.NoError(t, err)
	require.NotNil(t, svc)

	err = svc.Start(agdtest.ContextWithTimeout(t, dnssvctest.Timeout))
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(agdtest.ContextWithTimeout(t, dnssvctest.Timeout))
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

	reqType := dns.TypeA
	req := dnsservertest.CreateMessage(dnssvctest.DomainFQDN, reqType)

	clientAddr := &net.TCPAddr{IP: net.IP{1, 2, 3, 4}, Port: 12345}

	tlsServerName := strings.ReplaceAll(
		dnssvctest.DeviceIDWildcard,
		"*",
		string(dnssvctest.DeviceID),
	)

	ctx := context.Background()
	ctx = dnsserver.ContextWithServerInfo(ctx, &dnsserver.ServerInfo{
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
			require.Equal(pt, dnssvctest.DomainFQDN, m.Question[0].Name)

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

		ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
			StartTime:     time.Now(),
			TLSServerName: tlsServerName,
		})

		err := svc.Handle(ctx, testSrvGrpName, dnssvctest.ServerName, rw, req)
		require.NoError(t, err)

		resp := rw.Msg()
		dnsservertest.RequireResponse(t, req, resp, 1, dns.RcodeSuccess, false)

		assert.Equal(t, dnssvctest.DeviceID, <-profileDBCh)

		logEntry := <-querylogCh
		assert.Equal(t, dnssvctest.DomainFQDN, logEntry.DomainFQDN)
		assert.Equal(t, reqType, logEntry.RequestType)

		assert.Equal(t, "", <-geoIPCh)
		assert.Equal(t, dnssvctest.Domain, <-geoIPCh)

		dnsDBReqInfo := <-dnsDBCh
		assert.NotNil(t, dnsDBReqInfo)
		assert.Equal(t, agd.FilterRuleText(""), <-ruleStatCh)
	})

	t.Run("request_cname", func(t *testing.T) {
		const (
			cname                        = "cname.example.org"
			cnameRule agd.FilterRuleText = "||" + dnssvctest.Domain + "^$dnsrewrite=" + cname
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
					List: dnssvctest.FilterListID1,
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

		ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
			StartTime:     time.Now(),
			TLSServerName: tlsServerName,
		})

		err := svc.Handle(ctx, testSrvGrpName, dnssvctest.ServerName, rw, req)
		require.NoError(t, err)

		resp := rw.Msg()
		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 2)

		assert.Equal(t, []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   dnssvctest.DomainFQDN,
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

		assert.Equal(t, dnssvctest.DeviceID, <-profileDBCh)

		logEntry := <-querylogCh
		assert.Equal(t, dnssvctest.DomainFQDN, logEntry.DomainFQDN)
		assert.Equal(t, reqType, logEntry.RequestType)

		assert.Equal(t, "", <-geoIPCh)
		assert.Equal(t, cname, <-geoIPCh)

		dnsDBReqInfo := <-dnsDBCh
		assert.Equal(t, cname, dnsDBReqInfo.Host)
		assert.Equal(t, cnameRule, <-ruleStatCh)
	})
}
