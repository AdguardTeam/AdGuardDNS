package metrics_test

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/consul"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/ecscache"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/rediskv"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
)

// type check
//
// TODO(s.chzhen):  Move into the package itself when all metrics are
// refactored.
var (
	_ backendpb.CustomDomainStorageMetrics = (*metrics.BackendCustomDomainStorage)(nil)
	_ backendpb.GRPCMetrics                = (*metrics.BackendGRPC)(nil)
	_ backendpb.ProfileDBMetrics           = (*metrics.BackendProfileDB)(nil)
	_ backendpb.RemoteKVMetrics            = (*metrics.BackendRemoteKV)(nil)
	_ connlimiter.Metrics                  = (*metrics.ConnLimiter)(nil)
	_ billstat.Metrics                     = (*metrics.Billstat)(nil)
	_ consul.Metrics                       = (*metrics.Allowlist)(nil)
	_ dnscheck.Metrics                     = (*metrics.DNSCheck)(nil)
	_ dnsmsg.ClonerStat                    = metrics.ClonerStat{}
	_ dnssvc.MainMiddlewareMetrics         = (*metrics.DefaultMainMiddleware)(nil)
	_ dnssvc.MainMiddlewareMetrics         = metrics.MainMiddleware(nil)
	_ dnssvc.RatelimitMiddlewareMetrics    = (*metrics.DefaultRatelimitMiddleware)(nil)
	_ dnssvc.RatelimitMiddlewareMetrics    = metrics.RatelimitMiddleware(nil)
	_ ecscache.Metrics                     = (*metrics.ECSCache)(nil)
	_ filter.Metrics                       = (*metrics.Filter)(nil)
	_ geoip.Metrics                        = (*metrics.GeoIP)(nil)
	_ hashprefix.Metrics                   = (*metrics.HashPrefixFilter)(nil)
	_ profiledb.Metrics                    = (*metrics.ProfileDB)(nil)
	_ querylog.Metrics                     = (*metrics.QueryLog)(nil)
	_ rediskv.Metrics                      = (*metrics.RedisKV)(nil)
	_ rulestat.Metrics                     = (*metrics.RuleStat)(nil)
	_ tlsconfig.Metrics                    = (*metrics.TLSConfig)(nil)
)
