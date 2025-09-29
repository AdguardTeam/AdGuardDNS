package metrics_test

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
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
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
)

// type check
//
// TODO(s.chzhen):  Move into the package itself when all metrics are
// refactored.
var (
	_ access.ProfileMetrics                = (*metrics.AccessProfile)(nil)
	_ backendpb.CustomDomainStorageMetrics = (*metrics.BackendCustomDomainStorage)(nil)
	_ backendpb.GRPCMetrics                = (*metrics.BackendGRPC)(nil)
	_ backendpb.ProfileDBMetrics           = (*metrics.BackendProfileDB)(nil)
	_ backendpb.RemoteKVMetrics            = (*metrics.BackendRemoteKV)(nil)
	_ backendpb.TicketStorageMetrics       = (*metrics.BackendTicketStorage)(nil)
	_ billstat.Metrics                     = (*metrics.Billstat)(nil)
	_ bindtodevice.Metrics                 = (*metrics.BindToDevice)(nil)
	_ connlimiter.Metrics                  = (*metrics.ConnLimiter)(nil)
	_ consul.Metrics                       = (*metrics.Allowlist)(nil)
	_ dnscheck.Metrics                     = (*metrics.DNSCheck)(nil)
	_ dnsmsg.ClonerStat                    = (*metrics.ClonerStat)(nil)
	_ dnssvc.DeviceFinderMetrics           = (*metrics.DeviceFinder)(nil)
	_ dnssvc.InitialMiddlewareMetrics      = (*metrics.InitialMiddleware)(nil)
	_ dnssvc.MainMiddlewareMetrics         = (*metrics.MainMiddleware)(nil)
	_ dnssvc.RatelimitMiddlewareMetrics    = (*metrics.RatelimitMiddleware)(nil)
	_ ecscache.Metrics                     = (*metrics.ECSCache)(nil)
	_ filter.Metrics                       = (*metrics.Filter)(nil)
	_ geoip.Metrics                        = (*metrics.GeoIP)(nil)
	_ hashprefix.Metrics                   = (*metrics.HashPrefixFilter)(nil)
	_ profiledb.Metrics                    = (*metrics.ProfileDB)(nil)
	_ rulestat.Metrics                     = (*metrics.RuleStat)(nil)
	_ tlsconfig.CustomDomainDBMetrics      = (*metrics.CustomDomainDB)(nil)
	_ tlsconfig.ManagerMetrics             = (*metrics.TLSConfigManager)(nil)
	_ websvc.Metrics                       = (*metrics.WebSvc)(nil)
)
