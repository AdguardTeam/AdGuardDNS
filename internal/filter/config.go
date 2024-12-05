package filter

import "github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"

// Config is the sum type of [Storage.ForConfig] configurations.
//
// Acceptable implementations are:
//   - nil
//   - [*ConfigClient]
//   - [*ConfigGroup]
type Config interface {
	isConfig()
}

// ConfigClient is a [Config] for a client.
type ConfigClient struct {
	// Custom is the configuration for identification or construction of a
	// custom filter for a client.  It must not be nil.
	Custom *ConfigCustom

	// Parental is the configuration for parental-control filtering.  It must
	// not be nil.
	Parental *ConfigParental

	// RuleList is the configuration for rule-list based filtering.  It must not
	// be nil.
	RuleList *ConfigRuleList

	// SafeBrowsing is the configuration for safe-browsing filtering.  It must
	// not be nil.
	SafeBrowsing *ConfigSafeBrowsing
}

// type check
var _ Config = (*ConfigClient)(nil)

// isConfig implements the [Config] interface for *ConfigClient.
func (*ConfigClient) isConfig() {}

// ConfigCustom is the configuration for identification or construction of a
// custom filter for a client.
type ConfigCustom = internal.ConfigCustom

// ConfigParental is the configuration for parental-control filtering.
type ConfigParental struct {
	// PauseSchedule is the schedule for the pausing of the parental-control
	// filtering.  If it is nil, the parental-control filtering is never paused.
	// It is ignored if [ConfigParental.Enabled] is false.
	PauseSchedule *ConfigSchedule

	// BlockedServices are the IDs of the services blocked for this
	// parental-control configuration.  It is ignored if
	// [ConfigParental.Enabled] is false.
	BlockedServices []BlockedServiceID

	// Enabled shows whether the parental-control feature is enabled.
	Enabled bool

	// AdultBlockingEnabled shows whether the adult-blocking filtering should be
	// enforced.  It is ignored if [ConfigParental.Enabled] is false.
	AdultBlockingEnabled bool

	// SafeSearchGeneralEnabled shows whether the general safe-search filtering
	// should be enforced.  It is ignored if [ConfigParental.Enabled] is false.
	SafeSearchGeneralEnabled bool

	// SafeSearchYouTubeEnabled shows whether the YouTube safe-search filtering
	// should be enforced.  It is ignored if [ConfigParental.Enabled] is false.
	SafeSearchYouTubeEnabled bool
}

// ConfigRuleList is the configuration for rule-list based filtering.
type ConfigRuleList struct {
	// IDs are the IDs of the filtering rule lists used for this filtering
	// configuration.  They are ignored if [ConfigRuleList.Enabled] is false.
	IDs []ID

	// Enabled shows whether the rule-list based filtering is enabled.
	Enabled bool
}

// ConfigSafeBrowsing is the configuration for safe-browsing filtering.
type ConfigSafeBrowsing struct {
	// Enabled shows whether the safe-browsing hashprefix-based filtering should
	// is enabled.
	Enabled bool

	// DangerousDomainsEnabled shows whether the dangerous-domains safe-browsing
	// filtering should be enforced.  It is ignored if
	// [ConfigSafeBrowsing.Enabled] is false.
	DangerousDomainsEnabled bool

	// NewlyRegisteredDomainsEnabled shows whether the newly-registered domains
	// safe-browsing filtering should be enforced.  It is ignored if
	// [ConfigSafeBrowsing.Enabled] is false.
	NewlyRegisteredDomainsEnabled bool
}

// ConfigGroup is a [Config] for a filtering group.
type ConfigGroup struct {
	// Parental is the configuration for parental-control filtering.  It must
	// not be nil.
	Parental *ConfigParental

	// RuleList is the configuration for rule-list based filtering.  It must not
	// be nil.
	RuleList *ConfigRuleList

	// SafeBrowsing is the configuration for safe-browsing filtering.  It must
	// not be nil.
	SafeBrowsing *ConfigSafeBrowsing
}

// type check
var _ Config = (*ConfigGroup)(nil)

// isConfig implements the [Config] interface for *ConfigGroup.
func (*ConfigGroup) isConfig() {}
