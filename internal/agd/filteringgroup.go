package agd

import "github.com/AdguardTeam/AdGuardDNS/internal/filter"

// FilteringGroup represents a set of filtering settings.
//
// TODO(a.garipov):  Extract the pre-filtering booleans and logic into a new
// package.
type FilteringGroup struct {
	// FilterConfig is the configuration of the filters used for this filtering
	// group.  It must not be nil.
	FilterConfig *filter.ConfigGroup

	// ID is the unique ID of this filtering group.  It must be set.
	ID FilteringGroupID

	// BlockChromePrefetch shows if the Chrome prefetch proxy feature should be
	// disabled for requests using this filtering group.
	BlockChromePrefetch bool

	// BlockFirefoxCanary shows if Firefox canary domain is blocked for
	// requests using this filtering group.
	BlockFirefoxCanary bool

	// BlockPrivateRelay shows if Apple Private Relay is blocked for requests
	// using this filtering group.
	BlockPrivateRelay bool
}

// FilteringGroupID is the ID of a filter group.  It is an opaque string.
type FilteringGroupID string
