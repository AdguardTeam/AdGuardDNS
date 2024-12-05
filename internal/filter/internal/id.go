package internal

import (
	"fmt"
	"unicode/utf8"

	"github.com/AdguardTeam/golibs/errors"
)

// ID is the identifier of a filter.  It is an opaque string.
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

	err = validateInclusion(len(s), MaxIDLen, MinIDLen, unitByte)
	if err != nil {
		return IDNone, err
	}

	// Allow only the printable, non-whitespace ASCII characters.  Technically
	// we only need to exclude carriage return, line feed, and slash characters,
	// but let's be more strict just in case.
	if i, r := firstNonIDRune(s, true); i != -1 {
		return IDNone, fmt.Errorf("bad rune %q at index %d", r, i)
	}

	return ID(s), nil
}

// firstNonIDRune returns the first non-printable or non-ASCII rune and its
// index.  If slashes is true, it also looks for slashes.  If there are no such
// runes, i is -1.
//
// TODO(a.garipov):  Merge with the one in package agd once the refactoring is
// over.
func firstNonIDRune(s string, slashes bool) (i int, r rune) {
	for i, r = range s {
		if r < '!' || r > '~' || (slashes && r == '/') {
			return i, r
		}
	}

	return -1, 0
}

// unit name constants.
//
// TODO(a.garipov):  Merge with the one in package agd once the refactoring is
// over.
const (
	unitByte = "bytes"
	unitRune = "runes"
)

// validateInclusion returns an error if n is greater than max or less than min.
// unitName is used for error messages, see unitFoo constants.
//
// TODO(a.garipov): Consider switching min and max; the current order seems
// confusing.
//
// TODO(a.garipov):  Merge with the one in package agd once the refactoring is
// over.
func validateInclusion(n, max, min int, unitName string) (err error) {
	switch {
	case n > max:
		return fmt.Errorf("too long: got %d %s, max %d", n, unitName, max)
	case n < min:
		return fmt.Errorf("too short: got %d %s, min %d", n, unitName, min)
	default:
		return nil
	}
}

// Special ID values shared across the AdGuard DNS system.
//
// NOTE:  DO NOT change these as other parts of the system depend on these
// values.
const (
	// IDNone means that no filter were applied at all.
	IDNone ID = ""

	// IDBlockedService is the shared filter ID used when a request was blocked
	// by the service blocker.
	IDBlockedService ID = "blocked_service"

	// IDCustom is the special shared filter ID used when a request was filtered
	// by a custom profile rule.
	IDCustom ID = "custom"

	// IDAdultBlocking is the special shared filter ID used when a request was
	// filtered by the adult content blocking filter.
	IDAdultBlocking ID = "adult_blocking"

	// IDSafeBrowsing is the special shared filter ID used when a request was
	// filtered by the safe browsing filter.
	IDSafeBrowsing ID = "safe_browsing"

	// IDNewRegDomains is the special shared filter ID used when a request was
	// filtered by the newly registered domains filter.
	IDNewRegDomains ID = "newly_registered_domains"

	// IDGeneralSafeSearch is the shared filter ID used when a request was
	// modified by the general safe search filter.
	IDGeneralSafeSearch ID = "general_safe_search"

	// IDYoutubeSafeSearch is the special shared filter ID used when a request
	// was modified by the YouTube safe search filter.
	IDYoutubeSafeSearch ID = "youtube_safe_search"

	// IDAdGuardDNS is the special filter ID of the main AdGuard DNS
	// filtering-rule list.  For this list, rule statistics are collected.
	IDAdGuardDNS ID = "adguard_dns_filter"
)

// RuleText is the text of a single rule within a rule-list filter.
type RuleText string

// MaxRuleTextRuneLen is the maximum length of a filter rule in runes.
const MaxRuleTextRuneLen = 1024

// NewRuleText converts a simple string into a RuleText and makes sure that it's
// valid.  This should be preferred to a simple type conversion.
func NewRuleText(s string) (t RuleText, err error) {
	defer func() { err = errors.Annotate(err, "bad filter rule text %q: %w", s) }()

	err = validateInclusion(utf8.RuneCountInString(s), MaxRuleTextRuneLen, 0, unitRune)
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

	err = validateInclusion(len(s), MaxBlockedServiceIDLen, MinBlockedServiceIDLen, unitByte)
	if err != nil {
		return "", err
	}

	// Allow only the printable, non-whitespace ASCII characters.  Technically
	// we only need to exclude carriage return, line feed, and slash characters,
	// but let's be more strict just in case.
	if i, r := firstNonIDRune(s, true); i != -1 {
		return "", fmt.Errorf("bad char %q at index %d", r, i)
	}

	return BlockedServiceID(s), nil
}
