package cmd

import (
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
)

// filtersConfig contains the configuration for the filter lists and filtering
// storage to be used.
//
// TODO(a.garipov):  Add the timeout for the blocked-service index refresh.  It
// is currently hardcoded to 3 minutes.
type filtersConfig struct {
	// RuleListCache is the cache settings for the filtering rule-list.
	RuleListCache *fltRuleListCache `yaml:"rule_list_cache"`

	// CustomFilterCacheSize is the size of the LRU cache of compiled filtering
	// engines for profiles with custom filtering rules.
	CustomFilterCacheSize int `yaml:"custom_filter_cache_size"`

	// SafeSearchCacheSize is the size of the LRU cache of safe-search results.
	SafeSearchCacheSize int `yaml:"safe_search_cache_size"`

	// ResponseTTL is the TTL to set for DNS responses to requests for filtered
	// domains.
	ResponseTTL timeutil.Duration `yaml:"response_ttl"`

	// RefreshIvl defines how often AdGuard DNS refreshes the rule-based filters
	// from filter index.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`

	// RefreshTimeout is the timeout for the entire filter update operation.
	// Note that filter rule-list index and each filter rule-list update
	// operations have their own timeouts, see IndexRefreshTimeout and
	// RuleListRefreshTimeout.
	RefreshTimeout timeutil.Duration `yaml:"refresh_timeout"`

	// IndexRefreshTimeout is the timeout for the filter rule-list index update
	// operation.  See also RefreshTimeout for the entire filter update
	// operation.
	IndexRefreshTimeout timeutil.Duration `yaml:"index_refresh_timeout"`

	// RuleListRefreshTimeout is the timeout for the filter update operation of
	// each rule-list, which includes safe-search filters.  See also
	// RefreshTimeout for the entire filter update operation.
	RuleListRefreshTimeout timeutil.Duration `yaml:"rule_list_refresh_timeout"`

	// MaxSize is the maximum size of the downloadable filtering rule-list.
	MaxSize datasize.ByteSize `yaml:"max_size"`
}

// toInternal converts c to the filter storage configuration for the DNS server.
// cacheDir must exist.  c must be valid.
func (c *filtersConfig) toInternal(
	logger *slog.Logger,
	errColl errcoll.Interface,
	cacheManager agdcache.Manager,
	envs *environment,
	safeBrowsing *hashprefix.Filter,
	adultBlocking *hashprefix.Filter,
	newRegDomains *hashprefix.Filter,
) (conf *filter.DefaultStorageConfig) {
	var blockedServiceIndexURL *url.URL
	if envs.BlockedServiceEnabled {
		blockedServiceIndexURL = netutil.CloneURL(&envs.BlockedServiceIndexURL.URL)
	}

	var generalSafeSearchRulesURL *url.URL
	if envs.GeneralSafeSearchEnabled {
		generalSafeSearchRulesURL = netutil.CloneURL(&envs.GeneralSafeSearchURL.URL)
	}

	var youtubeSafeSearchRulesURL *url.URL
	if envs.YoutubeSafeSearchEnabled {
		youtubeSafeSearchRulesURL = netutil.CloneURL(&envs.YoutubeSafeSearchURL.URL)
	}

	return &filter.DefaultStorageConfig{
		BaseLogger:                logger,
		FilterIndexURL:            netutil.CloneURL(&envs.FilterIndexURL.URL),
		BlockedServiceIndexURL:    blockedServiceIndexURL,
		GeneralSafeSearchRulesURL: generalSafeSearchRulesURL,
		YoutubeSafeSearchRulesURL: youtubeSafeSearchRulesURL,
		SafeBrowsing:              safeBrowsing,
		AdultBlocking:             adultBlocking,
		NewRegDomains:             newRegDomains,
		Now:                       time.Now,
		ErrColl:                   errColl,
		CacheManager:              cacheManager,
		CacheDir:                  envs.FilterCachePath,
		CustomFilterCacheSize:     c.CustomFilterCacheSize,
		SafeSearchCacheSize:       c.SafeSearchCacheSize,
		// TODO(a.garipov): Consider making this configurable.
		SafeSearchCacheTTL:     1 * time.Hour,
		RuleListCacheSize:      c.RuleListCache.Size,
		RefreshIvl:             c.RefreshIvl.Duration,
		IndexRefreshTimeout:    c.IndexRefreshTimeout.Duration,
		RuleListRefreshTimeout: c.RuleListRefreshTimeout.Duration,
		UseRuleListCache:       c.RuleListCache.Enabled,
		MaxRuleListSize:        c.MaxSize,
	}
}

// type check
var _ validator = (*filtersConfig)(nil)

// validate implements the [validator] interface for *filtersConfig.
func (c *filtersConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.SafeSearchCacheSize <= 0:
		return newNotPositiveError("safe_search_cache_size", c.SafeSearchCacheSize)
	case c.ResponseTTL.Duration <= 0:
		return newNotPositiveError("response_ttl", c.ResponseTTL)
	case c.RefreshIvl.Duration <= 0:
		return newNotPositiveError("refresh_interval", c.RefreshIvl)
	case c.RefreshTimeout.Duration <= 0:
		return newNotPositiveError("refresh_timeout", c.RefreshTimeout)
	case c.IndexRefreshTimeout.Duration <= 0:
		return newNotPositiveError("index_refresh_timeout", c.IndexRefreshTimeout)
	case c.RuleListRefreshTimeout.Duration <= 0:
		return newNotPositiveError("rule_list_refresh_timeout", c.RuleListRefreshTimeout)
	case c.MaxSize <= 0:
		return newNotPositiveError("max_size", c.MaxSize)
	default:
		// Go on.
	}

	err = c.RuleListCache.validate()
	if err != nil {
		return fmt.Errorf("rule_list_cache: %w", err)
	}

	return nil
}

// fltRuleListCache contains filtering rule-list cache configuration.
type fltRuleListCache struct {
	// Size defines the size of the LRU cache of rule-list filtering results.
	Size int `yaml:"size"`

	// Enabled shows if the rule-list cache is enabled.  If it is false, the
	// rest of the settings are ignored.
	Enabled bool `yaml:"enabled"`
}

// type check
var _ validator = (*fltRuleListCache)(nil)

// validate implements the [validator] interface for *fltRuleListCache.
func (c *fltRuleListCache) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.Size <= 0:
		return newNotPositiveError("size", c.Size)
	default:
		return nil
	}
}
