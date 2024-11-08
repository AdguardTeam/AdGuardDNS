package dnssvc

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/cmd/plugin"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/prometheus/client_golang/prometheus"
)

// Config is the configuration of the AdGuard DNS service.
type Config struct {
	// Handlers are the handlers to use in this DNS service.
	Handlers Handlers

	// NewListener, when set, is used instead of the package-level function
	// [NewListener] when creating a DNS listener.
	//
	// TODO(a.garipov):  This is only used for tests.  Replace with a
	// [netext.ListenConfig].
	NewListener NewListenerFunc

	// Cloner is used to clone messages more efficiently by disposing of parts
	// of DNS responses for later reuse.  It must not be nil.
	Cloner *dnsmsg.Cloner

	// ControlConf is the configuration of socket options.
	ControlConf *netext.ControlConfig

	// ConnLimiter, if not nil, is used to limit the number of simultaneously
	// active stream-connections.
	ConnLimiter *connlimiter.Limiter

	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.  It must not be nil.
	ErrColl errcoll.Interface

	// NonDNS is the handler for non-DNS HTTP requests.  It must not be nil.
	NonDNS http.Handler

	// MetricsNamespace is a namespace for Prometheus metrics.  It must be a
	// valid Prometheus metric label.
	MetricsNamespace string

	// ServerGroups are the DNS server groups.  Each element must be non-nil.
	ServerGroups []*agd.ServerGroup

	// HandleTimeout defines the timeout for the entire handling of a single
	// query.  It must be greater than zero.
	HandleTimeout time.Duration
}

// NewListenerFunc is the type for DNS listener constructors.
type NewListenerFunc func(
	srv *agd.Server,
	baseConf dnsserver.ConfigBase,
	nonDNS http.Handler,
) (l Listener, err error)

// Listener is a type alias for dnsserver.Server to make internal naming more
// consistent.
type Listener = dnsserver.Server

// HandlersConfig is the configuration necessary to create or wrap the main DNS
// handler.
//
// TODO(a.garipov):  Consider adding validation functions.
type HandlersConfig struct {
	// BaseLogger is used to create loggers with custom prefixes for middlewares
	// and the service itself.  It must not be nil.
	BaseLogger *slog.Logger

	// Cloner is used to clone messages more efficiently by disposing of parts
	// of DNS responses for later reuse.  It must not be nil.
	Cloner *dnsmsg.Cloner

	// Cache is the configuration for the DNS cache.
	Cache *CacheConfig

	// HumanIDParser is used to normalize and parse human-readable device
	// identifiers.  It must not be nil if at least one server group has
	// profiles enabled.
	HumanIDParser *agd.HumanIDParser

	// Messages is the message constructor used to create blocked and other
	// messages for this DNS service.  It must not be nil.
	Messages *dnsmsg.Constructor

	// PluginRegistry is used to override configuration parameters.
	PluginRegistry *plugin.Registry

	// StructuredErrors is the configuration for the experimental Structured DNS
	// Errors feature in the profiles' message constructors.  It must not be
	// nil.
	StructuredErrors *dnsmsg.StructuredDNSErrorsConfig

	// AccessManager is used to block requests.  It must not be nil.
	AccessManager access.Interface

	// BillStat is used to collect billing statistics.  It must not be nil.
	BillStat billstat.Recorder

	// CacheManager is the global cache manager.  It must not be nil.
	CacheManager agdcache.Manager

	// DNSCheck is used by clients to check if they use AdGuard DNS.  It must
	// not be nil.
	DNSCheck dnscheck.Interface

	// DNSDB is used to update anonymous statistics about DNS queries.  It must
	// not be nil.
	DNSDB dnsdb.Interface

	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.  It must not be nil.
	ErrColl errcoll.Interface

	// FilterStorage is the storage of all filters.  It must not be nil.
	FilterStorage filter.Storage

	// GeoIP is the GeoIP database used to detect geographic data about IP
	// addresses in requests and responses.  It must not be nil.
	GeoIP geoip.Interface

	// Handler is the ultimate handler of the DNS query to be wrapped by
	// middlewares.  It must not be nil.
	Handler dnsserver.Handler

	// HashMatcher is the safe-browsing hash matcher for TXT queries.  It must
	// not be nil.
	HashMatcher filter.HashMatcher

	// ProfileDB is the AdGuard DNS profile database used to fetch data about
	// profiles, devices, and so on.  It must not be nil if at least one server
	// group has profiles enabled.
	ProfileDB profiledb.Interface

	// PrometheusRegisterer is used to register Prometheus metrics.  It must not
	// be nil.
	PrometheusRegisterer prometheus.Registerer

	// QueryLog is used to write the logs into.  It must not be nil.
	QueryLog querylog.Interface

	// RateLimit is used for allow or decline requests.  It must not be nil.
	RateLimit ratelimit.Interface

	// RuleStat is used to collect statistics about matched filtering rules and
	// rule lists.  It must not be nil.
	RuleStat rulestat.Interface

	// MetricsNamespace is a namespace for Prometheus metrics.  It must be a
	// valid Prometheus metric label.
	MetricsNamespace string

	// FilteringGroups are the DNS filtering groups.  Each element must be
	// non-nil.
	FilteringGroups map[agd.FilteringGroupID]*agd.FilteringGroup

	// ServerGroups are the DNS server groups for which to build handlers.  Each
	// element and its servers must be non-nil.
	ServerGroups []*agd.ServerGroup

	// EDEEnabled enables the addition of the Extended DNS Error (EDE) codes in
	// the profiles' message constructors.
	EDEEnabled bool
}

// Handlers contains the map of handlers for each server of each server group.
// The pointers are the same as those passed in a [HandlersConfig] to
// [NewHandlers].
type Handlers map[HandlerKey]dnsserver.Handler

// HandlerKey is a key for the [Handlers] map.
type HandlerKey struct {
	Server      *agd.Server
	ServerGroup *agd.ServerGroup
}

// CacheConfig is the configuration for the DNS cache.
type CacheConfig struct {
	// MinTTL is the minimum supported TTL for cache items.
	MinTTL time.Duration

	// ECSCount is the size of the DNS cache for domain names that support
	// ECS, in entries.  It must be greater than zero if [CacheConfig.CacheType]
	// is [CacheTypeECS].
	ECSCount int

	// NoECSCount is the size of the DNS cache for domain names that don't
	// support ECS, in entries.  It must be greater than zero if
	// [CacheConfig.CacheType] is [CacheTypeSimple] or [CacheTypeECS].
	NoECSCount int

	// Type is the cache type.  It must be valid.
	Type CacheType

	// OverrideCacheTTL shows if the TTL overriding logic should be used.
	OverrideCacheTTL bool
}

// CacheType is the type of the cache to use.
type CacheType uint8

// CacheType constants.
const (
	CacheTypeNone CacheType = iota + 1
	CacheTypeSimple
	CacheTypeECS
)
