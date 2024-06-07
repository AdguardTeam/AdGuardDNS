package agd

import (
	"fmt"
	"unicode/utf8"

	"github.com/AdguardTeam/golibs/errors"
)

// FilterListID is the ID of a filter list.  It is an opaque string.
type FilterListID string

// Special FilterListID values shared across the AdGuard DNS system.
//
// DO NOT change these as other parts of the system depend on these values.
const (
	// FilterListIDNone means that no filter were applied at all.
	FilterListIDNone FilterListID = ""

	// FilterListIDBlockedService is the shared filter-list ID used when a
	// request was blocked by the service blocker.
	FilterListIDBlockedService FilterListID = "blocked_service"

	// FilterListIDCustom is the special shared filter-list ID used when
	// a request was filtered by a custom profile rule.
	FilterListIDCustom FilterListID = "custom"

	// FilterListIDAdultBlocking is the special shared filter-list ID used when
	// a request was filtered by the adult content blocking filter.
	FilterListIDAdultBlocking FilterListID = "adult_blocking"

	// FilterListIDSafeBrowsing is the special shared filter-list ID used when
	// a request was filtered by the safe browsing filter.
	FilterListIDSafeBrowsing FilterListID = "safe_browsing"

	// FilterListIDNewRegDomains is the special shared filter-list ID used when
	// a request was filtered by the newly registered domains filter.
	FilterListIDNewRegDomains FilterListID = "newly_registered_domains"

	// FilterListIDGeneralSafeSearch is the shared filter-list ID used when
	// a request was modified by the general safe search filter.
	FilterListIDGeneralSafeSearch FilterListID = "general_safe_search"

	// FilterListIDYoutubeSafeSearch is the special shared filter-list ID used
	// when a request was modified by the YouTube safe search filter.
	FilterListIDYoutubeSafeSearch FilterListID = "youtube_safe_search"

	// FilterListIDAdGuardDNS is the special filter-list ID of the main AdGuard
	// DNS filtering-rule list.  For this list, rule statistics are collected.
	FilterListIDAdGuardDNS FilterListID = "adguard_dns_filter"

	// FilterListIDAdGuardPopup is the special filter-list ID of the AdGuard DNS
	// list of popup domains.
	FilterListIDAdGuardPopup FilterListID = "adguard_popup_filter"
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

// SupportsDNSRewrite returns true if the $dnsrewrite rules in filtering-rule
// lists with this ID should be processed.
func (id FilterListID) SupportsDNSRewrite() (ok bool) {
	switch id {
	case
		FilterListIDAdGuardPopup,
		FilterListIDCustom,
		FilterListIDGeneralSafeSearch,
		FilterListIDYoutubeSafeSearch:
		return true
	default:
		return false
	}
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

	// BlockDangerousDomains shows whether the dangerous domains safe browsing
	// filtering should be enforced.
	BlockDangerousDomains bool

	// BlockNewlyRegisteredDomains shows whether the newly registered domains
	// safe browsing filtering should be enforced.
	BlockNewlyRegisteredDomains bool

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
