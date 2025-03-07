package cmd

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
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
	//
	// TODO(a.garipov):  Rename to "custom_filter_cache_count"?
	CustomFilterCacheSize int `yaml:"custom_filter_cache_size"`

	// SafeSearchCacheSize is the size of the LRU cache of safe-search results.
	//
	// TODO(a.garipov):  Rename to "safe_search_cache_count"?
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

	// EDEEnabled enables the Extended DNS Errors feature.
	EDEEnabled bool `yaml:"ede_enabled"`

	// SDEEnabled enables the experimental Structured DNS Errors feature.
	SDEEnabled bool `yaml:"sde_enabled"`
}

// type check
var _ validate.Interface = (*filtersConfig)(nil)

// Validate implements the [validate.Interface] interface for *filtersConfig.
func (c *filtersConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.Positive("custom_filter_cache_size", c.CustomFilterCacheSize),
		validate.Positive("safe_search_cache_size", c.SafeSearchCacheSize),
		validate.Positive("response_ttl", c.ResponseTTL),
		validate.Positive("refresh_interval", c.RefreshIvl),
		validate.Positive("refresh_timeout", c.RefreshTimeout),
		validate.Positive("index_refresh_timeout", c.IndexRefreshTimeout),
		validate.Positive("rule_list_refresh_timeout", c.RuleListRefreshTimeout),
		validate.Positive("max_size", c.MaxSize),
	}

	if !c.EDEEnabled && c.SDEEnabled {
		errs = append(errs, errors.Error("ede must be enabled to enable sde"))
	}

	errs = validate.Append(errs, "rule_list_cache", c.RuleListCache)

	return errors.Join(errs...)
}

// fltRuleListCache contains filtering rule-list cache configuration.
type fltRuleListCache struct {
	// Size defines the size of the LRU cache of rule-list filtering results.
	//
	// TODO(a.garipov):  Rename to "count"?
	Size int `yaml:"size"`

	// Enabled shows if the rule-list cache is enabled.  If it is false, the
	// rest of the settings are ignored.
	Enabled bool `yaml:"enabled"`
}

// type check
var _ validate.Interface = (*fltRuleListCache)(nil)

// Validate implements the [validate.Interface] interface for *fltRuleListCache.
func (c *fltRuleListCache) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return validate.Positive("size", c.Size)
}
