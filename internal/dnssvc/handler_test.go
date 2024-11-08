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
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandlers(t *testing.T) {
	t.Parallel()

	accessMgr := &agdtest.AccessManager{
		OnIsBlockedHost: func(host string, qt uint16) (blocked bool) { panic("not implemented") },
		OnIsBlockedIP:   func(ip netip.Addr) (blocked bool) { panic("not implemented") },
	}

	billStat := &agdtest.BillStatRecorder{
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

	dnsCk := &agdtest.DNSCheck{
		OnCheck: func(
			_ context.Context,
			_ *dns.Msg,
			_ *agd.RequestInfo,
		) (resp *dns.Msg, err error) {
			panic("not implemented")
		},
	}

	dnsDB := &agdtest.DNSDB{
		OnRecord: func(_ context.Context, _ *dns.Msg, _ *agd.RequestInfo) {
			panic("not implemented")
		},
	}

	fltGrps := map[agd.FilteringGroupID]*agd.FilteringGroup{
		dnssvctest.FilteringGroupID: {
			ID:               dnssvctest.FilteringGroupID,
			RuleListIDs:      []agd.FilterListID{dnssvctest.FilterListID1},
			RuleListsEnabled: true,
		},
	}

	fltStrg := &agdtest.FilterStorage{
		OnFilterFromContext: func(_ context.Context, _ *agd.RequestInfo) (f filter.Interface) {
			panic("not implemented")
		},
		OnHasListID: func(_ agd.FilterListID) (ok bool) { panic("not implemented") },
	}

	hashMatcher := &agdtest.HashMatcher{
		OnMatchByPrefix: func(
			_ context.Context,
			_ string,
		) (hashes []string, matched bool, err error) {
			panic("not implemented")
		},
	}

	queryLog := &agdtest.QueryLog{
		OnWrite: func(_ context.Context, _ *querylog.Entry) (err error) {
			panic("not implemented")
		},
	}

	ruleStat := &agdtest.RuleStat{
		OnCollect: func(_ context.Context, _ agd.FilterListID, _ agd.FilterRuleText) {
			panic("not implemented")
		},
	}

	srv := dnssvctest.NewServer(dnssvctest.ServerName, agd.ProtoDoT, &agd.ServerBindData{
		AddrPort: dnssvctest.ServerAddrPort,
	})

	srvGrp := &agd.ServerGroup{
		DDR: &agd.DDR{
			Enabled: true,
		},
		TLS:             &agd.TLS{},
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
				BaseLogger:       slogutil.NewDiscardLogger(),
				Cloner:           agdtest.NewCloner(),
				Cache:            tc.cacheConf,
				HumanIDParser:    agd.NewHumanIDParser(),
				Messages:         agdtest.NewConstructor(t),
				PluginRegistry:   nil,
				StructuredErrors: agdtest.NewSDEConfig(true),
				AccessManager:    accessMgr,
				BillStat:         billStat,
				// TODO(a.garipov):  Create a test implementation?
				CacheManager:         agdcache.EmptyManager{},
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
				FilteringGroups:      fltGrps,
				ServerGroups:         []*agd.ServerGroup{srvGrp},
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
