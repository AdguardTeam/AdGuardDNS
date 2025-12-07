package dnssvc_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"path"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
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
//     the DeviceID with [dnssvctest.DomainForDevices].
//
// Each stub also uses the corresponding channels to send the data it receives
// from the service.  The channels must not be nil.  Each sending to a channel
// wrapped with [testutil.RequireSend] using [dnssvctest.Timeout].
//
// It also uses the [dnsservertest.NewDefaultHandler] to create the DNS handler.
func newTestService(
	t testing.TB,
	flt filter.Interface,
	errCollCh chan<- error,
	profileDBCh chan<- agd.DeviceID,
	querylogCh chan<- *querylog.Entry,
	geoIPCh chan<- string,
	dnsDBCh chan<- *agd.RequestInfo,
	ruleStatCh chan<- filter.RuleText,
) (svc *dnssvc.Service, srvAddr netip.AddrPort) {
	t.Helper()

	pt := testutil.PanicT{}

	dev := &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled:      false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID:               dnssvctest.DeviceID,
		FilteringEnabled: true,
	}

	prof := &agd.Profile{
		FilterConfig: &filter.ConfigClient{
			Custom: &filter.ConfigCustom{},
			Parental: &filter.ConfigParental{
				Categories: &filter.ConfigCategories{},
			},
			RuleList: &filter.ConfigRuleList{
				IDs:     []filter.ID{dnssvctest.FilterListID1},
				Enabled: true,
			},
			SafeBrowsing: &filter.ConfigSafeBrowsing{},
		},
		Access:                   access.EmptyProfile{},
		AdultBlockingMode:        nil,
		BlockingMode:             &dnsmsg.BlockingModeNullIP{},
		SafeBrowsingBlockingMode: nil,
		ID:                       dnssvctest.ProfileID,
		DeviceIDs:                container.NewMapSet(dnssvctest.DeviceID),
		FilteredResponseTTL:      agdtest.FilteredResponseTTL,
		FilteringEnabled:         true,
		QueryLogEnabled:          true,
	}

	profDB := agdtest.NewProfileDB()
	profDB.OnProfileByDeviceID = func(
		_ context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error) {
		testutil.RequireSend(pt, profileDBCh, id, dnssvctest.Timeout)

		return prof, dev, nil
	}

	accessManager := &agdtest.AccessManager{
		OnIsBlockedHost: func(host string, qt uint16) (blocked bool) {
			return false
		},
		OnIsBlockedIP: func(ip netip.Addr) (blocked bool) {
			return false
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

	geoIP := agdtest.NewGeoIP()
	geoIP.OnData = func(
		_ context.Context,
		host string,
		_ netip.Addr,
	) (l *geoip.Location, err error) {
		testutil.RequireSend(pt, geoIPCh, host, dnssvctest.Timeout)

		return loc, nil
	}

	fltStrg := &agdtest.FilterStorage{
		OnForConfig: func(_ context.Context, _ filter.Config) (f filter.Interface) {
			return flt
		},
		OnHasListID: func(id filter.ID) (ok bool) { panic(testutil.UnexpectedCall(id)) },
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
		OnCollect: func(_ context.Context, _ filter.ID, text filter.RuleText) {
			testutil.RequireSend(pt, ruleStatCh, text, dnssvctest.Timeout)
		},
	}

	rl := agdtest.NewRateLimit()
	rl.OnIsRateLimited = func(
		_ context.Context,
		_ *dns.Msg,
		_ netip.Addr,
	) (shouldDrop, isAllowlisted bool, err error) {
		return true, false, nil
	}

	srvGrps := []*dnssvc.ServerGroupConfig{{
		DDR: &dnssvc.DDRConfig{
			Enabled: true,
		},
		DeviceDomains:   []string{dnssvctest.DomainForDevices},
		Name:            dnssvctest.ServerGroupName,
		FilteringGroup:  dnssvctest.FilteringGroupID,
		Servers:         []*agd.Server{srv},
		ProfilesEnabled: true,
	}}

	fltGrp := &agd.FilteringGroup{
		FilterConfig: &filter.ConfigGroup{
			Parental: &filter.ConfigParental{
				Categories: &filter.ConfigCategories{},
			},
			RuleList: &filter.ConfigRuleList{
				IDs:     []filter.ID{dnssvctest.FilterListID1},
				Enabled: true,
			},
			SafeBrowsing: &filter.ConfigSafeBrowsing{},
		},
		ID: dnssvctest.FilteringGroupID,
	}

	hdlrConf := &dnssvc.HandlersConfig{
		BaseLogger: testLogger,
		Cache: &dnssvc.CacheConfig{
			Type: dnssvc.CacheTypeNone,
		},
		StructuredErrors: agdtest.NewSDEConfig(true),
		Cloner:           agdtest.NewCloner(),
		HumanIDParser:    agd.NewHumanIDParser(),
		Messages:         agdtest.NewConstructor(t),
		AccessManager:    accessManager,
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
		CacheManager:         agdcache.EmptyManager{},
		CustomDomainDB:       dnssvc.EmptyCustomDomainDB{},
		DNSCheck:             dnsCk,
		DNSDB:                dnsDB,
		ErrColl:              errColl,
		FilterStorage:        fltStrg,
		GeoIP:                geoIP,
		Handler:              dnsservertest.NewDefaultHandler(),
		HashMatcher:          hashprefix.NewMatcher(nil),
		ProfileDB:            profDB,
		PrometheusRegisterer: agdtest.NewTestPrometheusRegisterer(),
		QueryLog:             ql,
		RateLimit:            rl,
		RuleStat:             ruleStat,
		MetricsNamespace:     path.Base(t.Name()),
		NodeName:             t.Name(),
		FilteringGroups: map[agd.FilteringGroupID]*agd.FilteringGroup{
			dnssvctest.FilteringGroupID: fltGrp,
		},
		ServerGroups: srvGrps,
		EDEEnabled:   true,
	}

	ctx := context.Background()
	handlers, err := dnssvc.NewHandlers(ctx, hdlrConf)
	require.NoError(t, err)

	c := &dnssvc.Config{
		BaseLogger:           testLogger,
		Handlers:             handlers,
		NewListener:          newTestListenerFunc(tl),
		Cloner:               agdtest.NewCloner(),
		ErrColl:              errColl,
		NonDNS:               http.NotFoundHandler(),
		PrometheusRegisterer: prometheus.NewRegistry(),
		MetricsNamespace:     path.Base(t.Name()),
		ServerGroups:         srvGrps,
		HandleTimeout:        dnssvctest.Timeout,
	}

	svc, err = dnssvc.New(c)
	require.NoError(t, err)
	require.NotNil(t, svc)

	err = svc.Start(testutil.ContextWithTimeout(t, dnssvctest.Timeout))
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(testutil.ContextWithTimeout(t, dnssvctest.Timeout))
	})

	return svc, srvAddr
}

// TODO(a.garipov):  Refactor to test handlers separately from the service.
func TestService_Wrap(t *testing.T) {
	profileDBCh := make(chan agd.DeviceID, 1)
	querylogCh := make(chan *querylog.Entry, 1)
	geoIPCh := make(chan string, 2)
	dnsDBCh := make(chan *agd.RequestInfo, 1)
	ruleStatCh := make(chan filter.RuleText, 1)

	errCollCh := make(chan error, 1)
	go func() {
		for err := range errCollCh {
			require.NoError(t, err)
		}
	}()

	reqType := dns.TypeA
	req := dnsservertest.CreateMessage(dnssvctest.DomainFQDN, reqType)

	clientAddr := &net.TCPAddr{IP: net.IP{1, 2, 3, 4}, Port: 12345}

	ctx := context.Background()
	ctx = dnsserver.ContextWithServerInfo(ctx, &dnsserver.ServerInfo{
		Proto: agd.ProtoDoT,
	})

	t.Run("simple_success", func(t *testing.T) {
		flt := &agdtest.Filter{
			OnFilterRequest: func(
				_ context.Context,
				fltReq *filter.Request,
			) (r filter.Result, err error) {
				pt := testutil.PanicT{}
				require.NotEmpty(pt, fltReq.DNS.Question)
				require.Equal(pt, dnssvctest.DomainFQDN, fltReq.DNS.Question[0].Name)

				return nil, nil
			},
			OnFilterResponse: func(
				_ context.Context,
				fltResp *filter.Response,
			) (r filter.Result, err error) {
				pt := testutil.PanicT{}
				require.NotEmpty(pt, fltResp.DNS.Question)
				require.Equal(pt, dnssvctest.DomainFQDN, fltResp.DNS.Question[0].Name)

				return nil, nil
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
			TLSServerName: dnssvctest.DeviceIDSrvName,
		})

		err := svc.Handle(ctx, dnssvctest.ServerGroupName, dnssvctest.ServerName, rw, req)
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
		assert.Equal(t, filter.RuleText(""), <-ruleStatCh)
	})

	t.Run("request_cname", func(t *testing.T) {
		const (
			cname                     = "cname.example.org"
			cnameRule filter.RuleText = "||" + dnssvctest.Domain + "^$dnsrewrite=" + cname
		)

		cnameFQDN := dns.Fqdn(cname)

		flt := &agdtest.Filter{
			OnFilterRequest: func(
				_ context.Context,
				fltReq *filter.Request,
			) (r filter.Result, err error) {
				// Pretend a CNAME rewrite matched the request.
				mod := dnsmsg.Clone(fltReq.DNS)
				mod.Question[0].Name = cnameFQDN

				return &filter.ResultModifiedRequest{
					Msg:  mod,
					List: dnssvctest.FilterListID1,
					Rule: cnameRule,
				}, nil
			},
			OnFilterResponse: func(ctx context.Context, resp *filter.Response) (filter.Result, error) {
				panic(testutil.UnexpectedCall(ctx, resp))
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
			TLSServerName: dnssvctest.DeviceIDSrvName,
		})

		err := svc.Handle(ctx, dnssvctest.ServerGroupName, dnssvctest.ServerName, rw, req)
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
