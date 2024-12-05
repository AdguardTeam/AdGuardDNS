package filterstorage

import (
	"log/slog"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/c2h5oh/datasize"
)

// Config contains configuration for a default filter storage.
type Config struct {
	// BaseLogger is used to create loggers with custom prefixes for filters.
	// It must not be nil.
	BaseLogger *slog.Logger

	// Logger is used for logging the operation of the storage.  It must not be
	// nil.
	Logger *slog.Logger

	// BlockedServices is the configuration of a blocked-service filter for a
	// default filter storage.  It must not be nil
	BlockedServices *ConfigBlockedServices

	// Custom is the configuration of a custom filters storage for a default
	// filter storage.  It must not be nil
	Custom *ConfigCustom

	// HashPrefix is the hashprefix-filter configuration for a default filter
	// storage.  It must not be nil
	HashPrefix *ConfigHashPrefix

	// RuleLists is the rule-list configuration for a default filter storage.
	// It must not be nil.
	RuleLists *ConfigRuleLists

	// SafeSearchGeneral is the general safe-search configuration for a default
	// filter storage.  It must not be nil.
	SafeSearchGeneral *ConfigSafeSearch

	// SafeSearchYouTube is the YouTube safe-search configuration for a default
	// filter storage.  It must not be nil.
	SafeSearchYouTube *ConfigSafeSearch

	// CacheManager is the global cache manager.  It must not be nil.
	CacheManager agdcache.Manager

	// Clock is used for time-related operations, such as schedule checking.
	// It must not be nil.
	Clock agdtime.Clock

	// ErrColl is used to collect non-critical and rare errors as well as
	// refresh errors.  It must not be nil.
	ErrColl errcoll.Interface

	// Metrics are the metrics for the filters in the storage.
	Metrics filter.Metrics

	// CacheDir is the path to the directory where the cached filter files are
	// put.  It must not be empty and the directory must exist.
	CacheDir string
}

// ConfigBlockedServices is the blocked-service filter configuration for a
// default filter storage.
type ConfigBlockedServices struct {
	// IndexURL is the URL of the blocked-service filter index.  It must not be
	// modified after calling [New].  It must not be nil.  It is ignored if
	// [ConfigBlockedServices.Enabled] is false.
	IndexURL *url.URL

	// IndexMaxSize is the maximum size of the downloadable blocked-service
	// index content.  It must be positive.  It is ignored if
	// [ConfigBlockedServices.Enabled] is false.
	IndexMaxSize datasize.ByteSize

	// IndexRefreshTimeout is the timeout for the update of the blocked-service
	// index.  It must be positive.  It is ignored if
	// [ConfigBlockedServices.Enabled] is false.
	IndexRefreshTimeout time.Duration

	// IndexStaleness is the time after which the cached index file is
	// considered stale.  It must be positive.  It is ignored if
	// [ConfigBlockedServices.Enabled] is false.
	IndexStaleness time.Duration

	// ResultCacheCount is the count of items to keep in the LRU result cache of
	// the blocked-service filters.  It must be greater than zero.  It is
	// ignored if [ConfigBlockedServices.Enabled] is false.
	ResultCacheCount int

	// ResultCacheEnabled enables caching of results of the blocked-service
	// filters.  It is ignored if [ConfigBlockedServices.Enabled] is false.
	ResultCacheEnabled bool

	// Enabled shows whether the blocked-service filtering is enabled.
	Enabled bool
}

// ConfigCustom is the configuration of a custom filters storage for a default
// filter storage.
type ConfigCustom struct {
	// CacheCount is the count of items to keep in the LRU cache of custom
	// filters.  It must be greater than zero.
	CacheCount int
}

// ConfigHashPrefix is the hashprefix-filter configuration for a default filter
// storage.
type ConfigHashPrefix struct {
	// Adult is the optional hashprefix filter for adult content.  If nil, no
	// adult-content filtering is performed.
	Adult *hashprefix.Filter

	// Dangerous is the optional hashprefix filter for dangerous domains.  If
	// nil, no dangerous-domains filtering is performed.
	Dangerous *hashprefix.Filter

	// NewlyRegistered is the optional hashprefix filter for newly-registered
	// domains.  If nil, no filter of newly-registered domains is performed.
	NewlyRegistered *hashprefix.Filter
}

// ConfigRuleLists is the rule-list configuration for a default filter storage.
type ConfigRuleLists struct {
	// IndexURL is the URL of the rule-list filter index.  It must not be
	// modified after calling [New].  It must not be nil.
	IndexURL *url.URL

	// IndexMaxSize is the maximum size of the downloadable filter-index
	// content.  It must be positive.
	IndexMaxSize datasize.ByteSize

	// MaxSize is the maximum size of the content of a single rule-list filter.
	// It must be positive.
	MaxSize datasize.ByteSize

	// IndexRefreshTimeout is the timeout for the update of the rule-list filter
	// index.  It must be positive.
	IndexRefreshTimeout time.Duration

	// IndexStaleness is the time after which the cached index file is
	// considered stale.  It must be positive.
	IndexStaleness time.Duration

	// RefreshTimeout is the timeout for the update of a single rule-list
	// filter.  It must be positive.
	RefreshTimeout time.Duration

	// Staleness is the time after which the cached filter files are considered
	// stale.  It must be positive.
	Staleness time.Duration

	// ResultCacheCount is the count of items to keep in the LRU result cache of
	// a single rule-list filter.  It must be greater than zero.
	ResultCacheCount int

	// ResultCacheEnabled enables caching of results of the rule-list filters.
	ResultCacheEnabled bool
}

// ConfigSafeSearch is the single safe-search configuration for a default filter
// storage.
type ConfigSafeSearch struct {
	// URL is the HTTP(S) URL of the safe-search rules list.  It must not be
	// modified after calling [New].  It must not be nil.  It is ignored if
	// [ConfigSafeSearch.Enabled] is false.
	URL *url.URL

	// ID is the identifier of this safe-search filter.  It must not be empty.
	// It is ignored if [ConfigSafeSearch.Enabled] is false.
	ID filter.ID

	// MaxSize is the maximum size of the downloadable filter content.  It must
	// be positive.  It is ignored if [ConfigSafeSearch.Enabled] is false.
	MaxSize datasize.ByteSize

	// ResultCacheTTL is the time to live of the items in the result cache.  It
	// must be positive.  It is ignored if [ConfigSafeSearch.Enabled] is false.
	//
	// TODO(a.garipov):  Currently unused.  See AGDNS-398.
	ResultCacheTTL time.Duration

	// RefreshTimeout is the timeout for the update of a safe-search filter.  It
	// must be positive.  It is ignored if [ConfigSafeSearch.Enabled] is false.
	RefreshTimeout time.Duration

	// Staleness is the time after which the cached filter files are considered
	// stale.  It must be positive.  It is ignored if [ConfigSafeSearch.Enabled]
	// is false.
	Staleness time.Duration

	// ResultCacheCount is the count of items to keep in the LRU result cache of
	// a safe-search filter.  It must be positive.  It is ignored if
	// [ConfigSafeSearch.Enabled] is false.
	ResultCacheCount int

	// Enabled shows whether this safe-search filter is enabled.
	Enabled bool
}
