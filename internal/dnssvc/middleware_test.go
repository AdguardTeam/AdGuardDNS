package dnssvc_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_Wrap_withClient(t *testing.T) {
	// Part 1.  Server Configuration
	//
	// Configure a server with fakes to make sure that the wrapped handler
	// has all necessary entities and data in place.
	//
	// TODO(a.garipov): Put this thing into some kind of helper so that we
	// could create several such tests.

	const (
		id        agd.ProfileID    = "prof1234"
		devID     agd.DeviceID     = "dev1234"
		fltListID agd.FilterListID = "flt1234"
	)

	dev := &agd.Device{
		ID:               devID,
		FilteringEnabled: true,
	}

	prof := &agd.Profile{
		ID:                  id,
		Devices:             []*agd.Device{dev},
		RuleListIDs:         []agd.FilterListID{fltListID},
		FilteredResponseTTL: 10 * time.Second,
		FilteringEnabled:    true,
		QueryLogEnabled:     true,
	}

	dbDeviceIDs := make(chan agd.DeviceID, 1)
	db := &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			id agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			dbDeviceIDs <- id

			return prof, dev, nil
		},
		OnProfileByIP: func(
			ctx context.Context,
			ip netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
	}

	// Make sure that any panics and errors within handlers are caught and
	// that they fail the test by panicking.
	errCh := make(chan error, 1)
	go func() {
		pt := testutil.PanicT{}

		err, ok := <-errCh
		if !ok {
			return
		}

		require.NoError(pt, err)
	}()

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			errCh <- err
		},
	}

	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			_ agd.Country,
			_ agd.ASN,
			_ netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			panic("not implemented")
		},
		OnData: func(_ string, _ netip.Addr) (l *agd.Location, err error) {
			return &agd.Location{
				Country:   agd.CountryAD,
				Continent: agd.ContinentEU,
				ASN:       42,
			}, nil
		},
	}

	fltDomainCh := make(chan string, 1)
	flt := &agdtest.Filter{
		OnFilterRequest: func(
			_ context.Context,
			req *dns.Msg,
			_ *agd.RequestInfo,
		) (r filter.Result, err error) {
			fltDomainCh <- req.Question[0].Name

			return nil, nil
		},
		OnFilterResponse: func(
			_ context.Context,
			_ *dns.Msg,
			_ *agd.RequestInfo,
		) (r filter.Result, err error) {
			return nil, nil
		},
		OnClose: func() (err error) { panic("not implemented") },
	}

	fltStrg := &agdtest.FilterStorage{
		OnFilterFromContext: func(_ context.Context, _ *agd.RequestInfo) (f filter.Interface) {
			return flt
		},
		OnHasListID: func(_ agd.FilterListID) (ok bool) { panic("not implemented") },
	}

	logDomainCh := make(chan string, 1)
	logQTypeCh := make(chan dnsmsg.RRType, 1)
	var ql querylog.Interface = &agdtest.QueryLog{
		OnWrite: func(_ context.Context, e *querylog.Entry) (err error) {
			logDomainCh <- e.DomainFQDN
			logQTypeCh <- e.RequestType

			return nil
		},
	}

	srvAddr := netip.MustParseAddrPort("94.149.14.14:853")
	srvName := agd.ServerName("test_server_dns_tls")
	srvs := []*agd.Server{{
		DNSCrypt:      nil,
		TLS:           nil,
		Name:          srvName,
		Protocol:      agd.ProtoDoT,
		BindAddresses: []netip.AddrPort{srvAddr},
	}}

	tl := newTestListener()
	tl.onStart = func(_ context.Context) (err error) { return nil }
	tl.onShutdown = func(_ context.Context) (err error) { return nil }

	var h dnsserver.Handler = dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		r *dns.Msg,
	) (err error) {
		resp := &dns.Msg{}
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			A: net.IP{1, 2, 3, 4},
		})

		return rw.WriteMsg(ctx, r, resp)
	})

	dnsCk := &agdtest.DNSCheck{
		OnCheck: func(
			_ context.Context,
			_ *dns.Msg,
			_ *agd.RequestInfo,
		) (resp *dns.Msg, err error) {
			return nil, nil
		},
	}

	numDNSDBReq := 0
	dnsDB := &agdtest.DNSDB{
		OnRecord: func(_ context.Context, _ *dns.Msg, _ *agd.RequestInfo) {
			numDNSDBReq++
		},
	}

	numRuleStatReq := 0
	ruleStat := &agdtest.RuleStat{
		OnCollect: func(_ context.Context, _ agd.FilterListID, _ agd.FilterRuleText) {
			numRuleStatReq++
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
		OnCountResponses: func(_ context.Context, _ *dns.Msg, _ netip.Addr) {},
	}

	fltGrpID := agd.FilteringGroupID("1234")
	srvGrpName := agd.ServerGroupName("test_group")
	c := &dnssvc.Config{
		Messages: &dnsmsg.Constructor{
			FilteredResponseTTL: 10 * time.Second,
		},
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
		Upstream: &agd.Upstream{
			Server: netip.MustParseAddrPort("8.8.8.8:53"),
			FallbackServers: []netip.AddrPort{
				netip.MustParseAddrPort("1.1.1.1:53"),
			},
		},
		NewListener: newTestListenerFunc(tl),
		Handler:     h,
		RateLimit:   rl,
		FilteringGroups: map[agd.FilteringGroupID]*agd.FilteringGroup{
			fltGrpID: {
				ID:               fltGrpID,
				RuleListIDs:      []agd.FilterListID{fltListID},
				RuleListsEnabled: true,
			},
		},
		ServerGroups: []*agd.ServerGroup{{
			TLS: &agd.TLS{
				DeviceIDWildcards: []string{"*.dns.example.com"},
			},
			DDR: &agd.DDR{
				Enabled: true,
			},
			Name:           srvGrpName,
			FilteringGroup: fltGrpID,
			Servers:        srvs,
		}},
	}

	svc, err := dnssvc.New(c)
	require.NoError(t, err)
	require.NotNil(t, svc)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(context.Background())
	})

	err = svc.Start()
	require.NoError(t, err)

	// Part 2.  Testing Proper
	//
	// Create a context, a request, and a simple handler.  Wrap the handler
	// and make sure that all processing went as needed.

	domain := "example.org."
	reqType := dns.TypeA
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   domain,
			Qtype:  reqType,
			Qclass: dns.ClassINET,
		}},
	}

	ctx := context.Background()
	ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
		TLSServerName: string(devID) + ".dns.example.com",
	})
	ctx = dnsserver.ContextWithServerInfo(ctx, dnsserver.ServerInfo{
		Proto: agd.ProtoDoT,
	})
	ctx = dnsserver.ContextWithStartTime(ctx, time.Now())

	clientAddr := &net.TCPAddr{IP: net.IP{1, 2, 3, 4}, Port: 12345}
	rw := &testResponseWriter{
		onLocalAddr:  func() (a net.Addr) { return net.TCPAddrFromAddrPort(srvAddr) },
		onRemoteAddr: func() (a net.Addr) { return clientAddr },
		onWriteMsg: func(_ context.Context, _, _ *dns.Msg) (err error) {
			return nil
		},
	}
	err = svc.Handle(ctx, srvGrpName, srvName, rw, req)
	require.NoError(t, err)

	assert.Equal(t, devID, <-dbDeviceIDs)
	assert.Equal(t, domain, <-fltDomainCh)
	assert.Equal(t, domain, <-logDomainCh)
	assert.Equal(t, reqType, <-logQTypeCh)
	assert.Equal(t, 1, numDNSDBReq)
	assert.Equal(t, 1, numRuleStatReq)
}
