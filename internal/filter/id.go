package filter

import (
	"fmt"
	"unicode/utf8"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdvalidate"
	"github.com/AdguardTeam/golibs/errors"
)

// ID is the ID of a filter list.  It is an opaque string.
type ID string

// The maximum and minimum lengths of a filter ID.
const (
	MaxIDLen = 128
	MinIDLen = 1
)

// NewID converts a simple string into an ID and makes sure that it's valid.
// This should be preferred to a simple type conversion.
func NewID(s string) (id ID, err error) {
	defer func() { err = errors.Annotate(err, "bad filter id %q: %w", s) }()

	err = agdvalidate.Inclusion(len(s), MinIDLen, MaxIDLen, agdvalidate.UnitByte)
	if err != nil {
		return IDNone, err
	}

	// Allow only the printable, non-whitespace ASCII characters.  Technically
	// we only need to exclude carriage return, line feed, and slash characters,
	// but let's be more strict just in case.
	if i, r := agdvalidate.FirstNonIDRune(s, true); i != -1 {
		return IDNone, fmt.Errorf("bad rune %q at index %d", r, i)
	}

	return ID(s), nil
}

// Special ID values shared across the AdGuard DNS system.
//
// NOTE:  DO NOT change these as other parts of the system depend on these
// values.
//
// TODO(a.garipov):  Consider removing those that aren't used outside of the
// filter subpackages.
const (
	// IDNone means that no filter were applied at all.
	IDNone ID = ""

	// IDAdGuardDNS is the special filter ID of the main AdGuard DNS
	// filtering-rule list.  For this list, rule statistics are collected.
	IDAdGuardDNS ID = "adguard_dns_filter"

	// IDAdultBlocking is the special shared filter ID used when a request was
	// filtered by the adult content blocking filter.
	IDAdultBlocking ID = "adult_blocking"

	// IDBlockedService is the shared filter ID used when a request was blocked
	// by the service blocker.
	IDBlockedService ID = "blocked_service"

	// IDCustom is the special shared filter ID used when a request was filtered
	// by a custom profile rule.
	IDCustom ID = "custom"

	// IDGeneralSafeSearch is the shared filter ID used when a request was
	// modified by the general safe search filter.
	IDGeneralSafeSearch ID = "general_safe_search"

	// IDNewRegDomains is the special shared filter ID used when a request was
	// filtered by the newly registered domains filter.
	IDNewRegDomains ID = "newly_registered_domains"

	// IDSafeBrowsing is the special shared filter ID used when a request was
	// filtered by the safe browsing filter.
	IDSafeBrowsing ID = "safe_browsing"

	// IDYoutubeSafeSearch is the special shared filter ID used when a request
	// was modified by the YouTube safe search filter.
	IDYoutubeSafeSearch ID = "youtube_safe_search"
)

// RuleText is the text of a single rule within a rule-list filter.
type RuleText string

// MaxRuleTextRuneLen is the maximum length of a filter rule in runes.
const MaxRuleTextRuneLen = 1024

// NewRuleText converts a simple string into a RuleText and makes sure that it's
// valid.  This should be preferred to a simple type conversion.
func NewRuleText(s string) (t RuleText, err error) {
	defer func() { err = errors.Annotate(err, "bad filter rule text %q: %w", s) }()

	err = agdvalidate.Inclusion(
		utf8.RuneCountInString(s),
		0,
		MaxRuleTextRuneLen,
		agdvalidate.UnitRune,
	)
	if err != nil {
		return "", err
	}

	return RuleText(s), nil
}

// BlockedServiceID is the ID of a blocked service.  While these are usually
// human-readable, clients should treat them as opaque strings.
//
// When a request is blocked by the service blocker, this ID is used as the
// text of the blocking rule.
type BlockedServiceID string

// The maximum and minimum lengths of a blocked service ID.
const (
	MaxBlockedServiceIDLen = 64
	MinBlockedServiceIDLen = 1
)

// NewBlockedServiceID converts a simple string into a BlockedServiceID and
// makes sure that it's valid.  This should be preferred to a simple type
// conversion.
func NewBlockedServiceID(s string) (id BlockedServiceID, err error) {
	defer func() { err = errors.Annotate(err, "bad blocked service id %q: %w", s) }()

	err = agdvalidate.Inclusion(
		len(s),
		MinBlockedServiceIDLen,
		MaxBlockedServiceIDLen,
		agdvalidate.UnitByte,
	)
	if err != nil {
		return "", err
	}

	// Allow only the printable, non-whitespace ASCII characters.  Technically
	// we only need to exclude carriage return, line feed, and slash characters,
	// but let's be more strict just in case.
	if i, r := agdvalidate.FirstNonIDRune(s, true); i != -1 {
		return "", fmt.Errorf("bad char %q at index %d", r, i)
	}

	return BlockedServiceID(s), nil
}
