package metrics_test

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/consul"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/rediskv"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
)

// type check
//
// TODO(s.chzhen):  Move into the package itself when all metrics are
// refactored.
var (
	_ backendpb.GRPCMetrics             = (*metrics.BackendGRPC)(nil)
	_ backendpb.ProfileDBMetrics        = (*metrics.BackendProfileDB)(nil)
	_ backendpb.RemoteKVMetrics         = (*metrics.BackendRemoteKV)(nil)
	_ billstat.Metrics                  = (*metrics.Billstat)(nil)
	_ consul.Metrics                    = (*metrics.Allowlist)(nil)
	_ dnsmsg.ClonerStat                 = metrics.ClonerStat{}
	_ dnssvc.MainMiddlewareMetrics      = (*metrics.DefaultMainMiddleware)(nil)
	_ dnssvc.MainMiddlewareMetrics      = metrics.MainMiddleware(nil)
	_ dnssvc.RatelimitMiddlewareMetrics = (*metrics.DefaultRatelimitMiddleware)(nil)
	_ dnssvc.RatelimitMiddlewareMetrics = metrics.RatelimitMiddleware(nil)
	_ filter.Metrics                    = (*metrics.Filter)(nil)
	_ profiledb.Metrics                 = (*metrics.ProfileDB)(nil)
	_ rediskv.Metrics                   = (*metrics.RedisKV)(nil)
	_ tlsconfig.Metrics                 = (*metrics.TLSConfig)(nil)
)
