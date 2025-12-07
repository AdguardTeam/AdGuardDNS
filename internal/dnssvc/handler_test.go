package dnssvc_test

import (
	"context"
	"net/netip"
	"path"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandlers(t *testing.T) {
	t.Parallel()

	accessMgr := &agdtest.AccessManager{
		OnIsBlockedHost: func(host string, qt uint16) (blocked bool) {
			panic(testutil.UnexpectedCall(host, qt))
		},
		OnIsBlockedIP: func(ip netip.Addr) (blocked bool) { panic(testutil.UnexpectedCall(ip)) },
	}

	billStat := &agdtest.BillStatRecorder{
		OnRecord: func(
			ctx context.Context,
			id agd.DeviceID,
			ctry geoip.Country,
			asn geoip.ASN,
			start time.Time,
			proto agd.Protocol,
		) {
			panic(testutil.UnexpectedCall(ctx, id, ctry, asn, start, proto))
		},
	}

	dnsCk := &agdtest.DNSCheck{
		OnCheck: func(
			ctx context.Context,
			req *dns.Msg,
			ri *agd.RequestInfo,
		) (resp *dns.Msg, err error) {
			panic(testutil.UnexpectedCall(ctx, req, ri))
		},
	}

	dnsDB := &agdtest.DNSDB{
		OnRecord: func(ctx context.Context, resp *dns.Msg, ri *agd.RequestInfo) {
			panic(testutil.UnexpectedCall(ctx, resp, ri))
		},
	}

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

	fltGrps := map[agd.FilteringGroupID]*agd.FilteringGroup{
		dnssvctest.FilteringGroupID: fltGrp,
	}

	fltStrg := &agdtest.FilterStorage{
		OnForConfig: func(ctx context.Context, c filter.Config) (f filter.Interface) {
			panic(testutil.UnexpectedCall(ctx, c))
		},
		OnHasListID: func(id filter.ID) (ok bool) { panic(testutil.UnexpectedCall(id)) },
	}

	hashMatcher := &agdtest.HashMatcher{
		OnMatchByPrefix: func(
			ctx context.Context,
			host string,
		) (hashes []string, matched bool, err error) {
			panic(testutil.UnexpectedCall(ctx, host))
		},
	}

	queryLog := &agdtest.QueryLog{
		OnWrite: func(ctx context.Context, e *querylog.Entry) (err error) {
			panic(testutil.UnexpectedCall(ctx, e))
		},
	}

	ruleStat := &agdtest.RuleStat{
		OnCollect: func(ctx context.Context, id filter.ID, text filter.RuleText) {
			panic(testutil.UnexpectedCall(ctx, id, text))
		},
	}

	srv := dnssvctest.NewServer(dnssvctest.ServerName, agd.ProtoDoT, &agd.ServerBindData{
		AddrPort: dnssvctest.ServerAddrPort,
	})

	srvGrp := &dnssvc.ServerGroupConfig{
		DDR: &dnssvc.DDRConfig{
			Enabled: true,
		},
		Name:            dnssvctest.ServerGroupName,
		FilteringGroup:  dnssvctest.FilteringGroupID,
		Servers:         []*agd.Server{srv},
		ProfilesEnabled: true,
	}

	testCases := []struct {
		cacheConf *dnssvc.CacheConfig
		name      string
	}{{
		cacheConf: &dnssvc.CacheConfig{
			Type: dnssvc.CacheTypeNone,
		},
		name: "no_cache",
	}, {
		cacheConf: &dnssvc.CacheConfig{
			MinTTL:           10 * time.Second,
			NoECSCount:       100,
			Type:             dnssvc.CacheTypeSimple,
			OverrideCacheTTL: true,
		},
		name: "cache_simple",
	}, {
		cacheConf: &dnssvc.CacheConfig{
			MinTTL:           10 * time.Second,
			ECSCount:         100,
			NoECSCount:       100,
			Type:             dnssvc.CacheTypeECS,
			OverrideCacheTTL: true,
		},
		name: "cache_ecs",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			handlers, err := dnssvc.NewHandlers(ctx, &dnssvc.HandlersConfig{
				BaseLogger:            testLogger,
				Cloner:                agdtest.NewCloner(),
				Cache:                 tc.cacheConf,
				HumanIDParser:         agd.NewHumanIDParser(),
				MainMiddlewareMetrics: nil,
				Messages:              agdtest.NewConstructor(t),
				PostInitialMiddleware: nil,
				StructuredErrors:      agdtest.NewSDEConfig(true),
				AccessManager:         accessMgr,
				BillStat:              billStat,
				// TODO(a.garipov):  Create a test implementation?
				CacheManager: agdcache.EmptyManager{},
				// TODO(a.garipov):  Create a test implementation?
				CustomDomainDB:       dnssvc.EmptyCustomDomainDB{},
				DNSCheck:             dnsCk,
				DNSDB:                dnsDB,
				ErrColl:              agdtest.NewErrorCollector(),
				FilterStorage:        fltStrg,
				GeoIP:                agdtest.NewGeoIP(),
				Handler:              dnsservertest.NewPanicHandler(),
				HashMatcher:          hashMatcher,
				ProfileDB:            agdtest.NewProfileDB(),
				PrometheusRegisterer: agdtest.NewTestPrometheusRegisterer(),
				QueryLog:             queryLog,
				RateLimit:            agdtest.NewRateLimit(),
				RuleStat:             ruleStat,
				MetricsNamespace:     path.Base(t.Name()),
				NodeName:             t.Name(),
				FilteringGroups:      fltGrps,
				ServerGroups:         []*dnssvc.ServerGroupConfig{srvGrp},
				EDEEnabled:           true,
			})
			require.NoError(t, err)

			assert.Len(t, handlers, 1)

			for k, v := range handlers {
				assert.Same(t, srv, k.Server)
				assert.Same(t, srvGrp, k.ServerGroup)
				assert.NotNil(t, v)

				break
			}
		})
	}
}
