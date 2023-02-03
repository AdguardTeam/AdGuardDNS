package agd

import (
	"fmt"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/AdguardTeam/golibs/errors"
)

// Filter Lists

// FilterList is a list of filter rules.
type FilterList struct {
	// URL is the URL used to refresh the filter.
	URL *url.URL

	// ID is the unique ID of this filter.  It will also be used to create the
	// cache file.
	ID FilterListID

	// RefreshIvl is the interval that defines how often a filter should be
	// refreshed.  It is also used to check if the cached file is fresh enough.
	RefreshIvl time.Duration
}

// FilterListID is the ID of a filter list.  It is an opaque string.
type FilterListID string

// Special FilterListID values shared across the AdGuard DNS system.
//
// DO NOT change these as other parts of the system depend on these values.
const (
	// FilterListIDNone means that no filter were applied at all.
	FilterListIDNone FilterListID = ""

	// FilterListIDBlockedService is the shared filter list ID used when a
	// request was blocked by the service blocker.
	FilterListIDBlockedService FilterListID = "blocked_service"

	// FilterListIDCustom is the special shared filter list ID used when
	// a request was filtered by a custom profile rule.
	FilterListIDCustom FilterListID = "custom"

	// FilterListIDAdultBlocking is the special shared filter list ID used when
	// a request was filtered by the adult content blocking filter.
	FilterListIDAdultBlocking FilterListID = "adult_blocking"

	// FilterListIDSafeBrowsing is the special shared filter list ID used when
	// a request was filtered by the safe browsing filter.
	FilterListIDSafeBrowsing FilterListID = "safe_browsing"

	// FilterListIDGeneralSafeSearch is the shared filter list ID used when
	// a request was modified by the general safe search filter.
	FilterListIDGeneralSafeSearch FilterListID = "general_safe_search"

	// FilterListIDYoutubeSafeSearch is the special shared filter list ID used
	// when a request was modified by the YouTube safe search filter.
	FilterListIDYoutubeSafeSearch FilterListID = "youtube_safe_search"
)

// The maximum and minimum lengths of a filter list ID.
const (
	MaxFilterListIDLen = 128
	MinFilterListIDLen = 1
)

// NewFilterListID converts a simple string into a FilterListID and makes sure
// that it's valid.  This should be preferred to a simple type conversion.
func NewFilterListID(s string) (id FilterListID, err error) {
	defer func() { err = errors.Annotate(err, "bad filter list id %q: %w", s) }()

	err = ValidateInclusion(len(s), MaxFilterListIDLen, MinFilterListIDLen, UnitByte)
	if err != nil {
		return FilterListIDNone, err
	}

	// Allow only the printable, non-whitespace ASCII characters.  Technically
	// we only need to exclude carriage return, line feed, and slash characters,
	// but let's be more strict just in case.
	if i, r := firstNonIDRune(s, true); i != -1 {
		return FilterListIDNone, fmt.Errorf("bad rune %q at index %d", r, i)
	}

	return FilterListID(s), nil
}

// FilterRuleText is the text of a single rule within a filter.
type FilterRuleText string

// MaxFilterRuleTextRuneLen is the maximum length of a filter rule in runes.
const MaxFilterRuleTextRuneLen = 1024

// NewFilterRuleText converts a simple string into a FilterRuleText and makes
// sure that it's valid.  This should be preferred to a simple type conversion.
func NewFilterRuleText(s string) (t FilterRuleText, err error) {
	defer func() { err = errors.Annotate(err, "bad filter rule text %q: %w", s) }()

	err = ValidateInclusion(utf8.RuneCountInString(s), MaxFilterRuleTextRuneLen, 0, UnitRune)
	if err != nil {
		return "", err
	}

	return FilterRuleText(s), nil
}

// FilteringGroup represents a set of filtering settings.
//
// TODO(a.garipov): Consider making it closer to the config file and the backend
// response by grouping parental, rule list, and safe browsing settings into
// separate structs.
type FilteringGroup struct {
	// ID is the unique ID of this filtering group.
	ID FilteringGroupID

	// RuleListIDs are the filtering rule list IDs used for this filtering
	// group.  They are ignored if RuleListsEnabled is false.
	RuleListIDs []FilterListID

	// RuleListsEnabled shows whether the rule-list based filtering is enabled.
	// This must be true in order for all parameters below to work.
	RuleListsEnabled bool

	// ParentalEnabled shows whether the parental protection functionality is
	// enabled.  This must be true in order for all parameters below to
	// work.
	ParentalEnabled bool

	// BlockAdult shows whether the adult content blocking safe browsing
	// filtering should be enforced.
	BlockAdult bool

	// SafeBrowsingEnabled shows whether the general safe browsing filtering
	// should be enforced.
	SafeBrowsingEnabled bool

	// GeneralSafeSearch shows whether the general safe search filtering should
	// be enforced.
	GeneralSafeSearch bool

	// YoutubeSafeSearch shows whether the YouTube safe search filtering should
	// be enforced.
	YoutubeSafeSearch bool

	// BlockPrivateRelay shows if Apple Private Relay is blocked for requests
	// using this filtering group.
	BlockPrivateRelay bool

	// BlockFirefoxCanary shows if Firefox canary domain is blocked for
	// requests using this filtering group.
	BlockFirefoxCanary bool
}

// FilteringGroupID is the ID of a filter group.  It is an opaque string.
type FilteringGroupID string
