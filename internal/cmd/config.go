package cmd

import (
	"fmt"
	"os"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"gopkg.in/yaml.v2"
)

// configuration represents the on-disk configuration of AdGuard DNS.  The order
// of the fields should generally not be altered.
//
// TODO(a.garipov): Consider collecting all validation errors instead of
// quitting after the first one.
type configuration struct {
	// RateLimit is the rate limiting configuration.
	RateLimit *rateLimitConfig `yaml:"ratelimit"`

	// Cache is the DNS cache configuration.
	Cache *cacheConfig `yaml:"cache"`

	// Upstream is the configuration of upstream servers for the DNS servers.
	Upstream *upstreamConfig `yaml:"upstream"`

	// DNSDB is the configuration of DNSDB buffer.
	DNSDB *dnsDBConfig `yaml:"dnsdb"`

	// DNSDB is the configuration of common DNS settings.
	DNS *dnsConfig `yaml:"dns"`

	// Backend is the AdGuard HTTP backend service configuration.  See the
	// environments type for more backend parameters.
	Backend *backendConfig `yaml:"backend"`

	// QueryLog is the additional query log configuration.  See the environments
	// type for more query log parameters.
	QueryLog *queryLogConfig `yaml:"query_log"`

	// GeoIP is the additional GeoIP database configuration.  See the
	// environments type for more GeoIP database parameters.
	GeoIP *geoIPConfig `yaml:"geoip"`

	// Check is the configuration for the DNS server checker.
	Check *checkConfig `yaml:"check"`

	// Web is the configuration for the DNS-over-HTTP server.
	Web *webConfig `yaml:"web"`

	// SafeBrowsing is the AdGuard general safe browsing filter configuration.
	SafeBrowsing *safeBrowsingConfig `yaml:"safe_browsing"`

	// AdultBlocking is the AdGuard adult content blocking filter configuration.
	AdultBlocking *safeBrowsingConfig `yaml:"adult_blocking"`

	// Filters contains the configuration for the filter lists and filtering
	// storage to be used.  They are used by filtering groups below.
	Filters *filtersConfig `yaml:"filters"`

	// ConnectivityCheck is the connectivity check configuration.
	ConnectivityCheck *connCheckConfig `yaml:"connectivity_check"`

	// InterfaceListeners is the configuration for the network interface
	// listeners and their common parameters.
	InterfaceListeners *interfaceListenersConfig `yaml:"interface_listeners"`

	// Network is the configuration for network listeners.
	Network *network `yaml:"network"`

	// Access is the configuration of the service managing access control.
	Access *accessConfig `yaml:"access"`

	// AdditionalMetricsInfo is extra information, which is exposed by metrics.
	AdditionalMetricsInfo additionalInfo `yaml:"additional_metrics_info"`

	// FilteringGroups are the predefined filtering configurations that are used
	// for different server groups.
	FilteringGroups filteringGroups `yaml:"filtering_groups"`

	// ServerGroups are the DNS server groups.
	ServerGroups serverGroups `yaml:"server_groups"`
}

// type check
var _ validate.Interface = (*configuration)(nil)

// Validate implements the [validate.Interface] interface for *configuration.
func (c *configuration) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	// Keep this in the same order as the fields in the config.
	validators := container.KeyValues[string, validate.Interface]{{
		Key:   "ratelimit",
		Value: c.RateLimit,
	}, {
		Key:   "upstream",
		Value: c.Upstream,
	}, {
		Key:   "cache",
		Value: c.Cache,
	}, {
		Key:   "dnsdb",
		Value: c.DNSDB,
	}, {
		Key:   "dns",
		Value: c.DNS,
	}, {
		Key:   "backend",
		Value: c.Backend,
	}, {
		Key:   "query_log",
		Value: c.QueryLog,
	}, {
		Key:   "geoip",
		Value: c.GeoIP,
	}, {
		Key:   "check",
		Value: c.Check,
	}, {
		Key:   "web",
		Value: c.Web,
	}, {
		Key:   "safe_browsing",
		Value: c.SafeBrowsing,
	}, {
		Key:   "adult_blocking",
		Value: c.AdultBlocking,
	}, {
		Key:   "filters",
		Value: c.Filters,
	}, {
		Key:   "filtering_groups",
		Value: c.FilteringGroups,
	}, {
		Key:   "server_groups",
		Value: c.ServerGroups,
	}, {
		Key:   "connectivity_check",
		Value: c.ConnectivityCheck,
	}, {
		Key:   "interface_listeners",
		Value: c.InterfaceListeners,
	}, {
		Key:   "network",
		Value: c.Network,
	}, {
		Key:   "access",
		Value: c.Access,
	}, {
		Key:   "additional_metrics_info",
		Value: c.AdditionalMetricsInfo,
	}}

	var errs []error
	for _, kv := range validators {
		errs = validate.Append(errs, kv.Key, kv.Value)
	}

	return errors.Join(errs...)
}

// isProfilesEnabled returns true if there is at least one server group with
// profiles enabled.  conf must be valid.
func (c *configuration) isProfilesEnabled() (ok bool) {
	for _, s := range c.ServerGroups {
		if s.ProfilesEnabled {
			return true
		}
	}

	return false
}

// parseConfig reads the configuration.
func parseConfig(confPath string) (c *configuration, err error) {
	// #nosec G304 -- Trust the path to the configuration file that is given
	// from the environment.
	yamlFile, err := os.ReadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	c = &configuration{}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return c, nil
}
