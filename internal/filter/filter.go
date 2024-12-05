// Package filter contains the filter interface and its implementations along
// with types that combine them based on the settings in profile and filtering
// group.
package filter

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
)

// Interface is the DNS request and response filter interface.
type Interface = internal.Interface

// Empty is an [Interface] implementation that always returns nil.
type Empty = internal.Empty

// Request contains information about a request being filtered.
type Request = internal.Request

// Response contains information about a response being filtered.
type Response = internal.Response

// Result is a sum type of all possible filtering actions.  See the following
// types as implementations:
//
//   - [*ResultAllowed]
//   - [*ResultBlocked]
//   - [*ResultModifiedResponse]
//   - [*ResultModifiedRequest]
type Result = internal.Result

// ResultAllowed means that this request or response was allowed by an allowlist
// rule within the given filter list.
type ResultAllowed = internal.ResultAllowed

// ResultBlocked means that this request or response was blocked by a blocklist
// rule within the given filter list.
type ResultBlocked = internal.ResultBlocked

// ResultModifiedResponse means that this response was rewritten or modified by
// a rewrite rule within the given filter list.
type ResultModifiedResponse = internal.ResultModifiedResponse

// ResultModifiedRequest means that this request was modified by a rewrite rule
// within the given filter list.
type ResultModifiedRequest = internal.ResultModifiedRequest

// ID is the ID of a filter list.  It is an opaque string.
type ID = internal.ID

// Special ID values shared across the AdGuard DNS system.
//
// NOTE:  DO NOT change these as other parts of the system depend on these
// values.
//
// TODO(a.garipov):  Consider removing those that aren't used outside of the
// filter subpackages.
const (
	IDNone = internal.IDNone

	IDAdGuardDNS        = internal.IDAdGuardDNS
	IDAdultBlocking     = internal.IDAdultBlocking
	IDBlockedService    = internal.IDBlockedService
	IDCustom            = internal.IDCustom
	IDGeneralSafeSearch = internal.IDGeneralSafeSearch
	IDNewRegDomains     = internal.IDNewRegDomains
	IDSafeBrowsing      = internal.IDSafeBrowsing
	IDYoutubeSafeSearch = internal.IDYoutubeSafeSearch
)

// NewID converts a simple string into an ID and makes sure that it's valid.
// This should be preferred to a simple type conversion.
func NewID(s string) (id ID, err error) { return internal.NewID(s) }

// RuleText is the text of a single rule within a rule-list filter.
type RuleText = internal.RuleText

// NewRuleText converts a simple string into an RuleText and makes sure that
// it's valid.  This should be preferred to a simple type conversion.
func NewRuleText(s string) (id RuleText, err error) { return internal.NewRuleText(s) }

// BlockedServiceID is the ID of a blocked service.  While these are usually
// human-readable, clients should treat them as opaque strings.
//
// When a request is blocked by the service blocker, this ID is used as the
// text of the blocking rule.
type BlockedServiceID = internal.BlockedServiceID

// NewBlockedServiceID converts a simple string into a BlockedServiceID and
// makes sure that it's valid.  This should be preferred to a simple type
// conversion.
func NewBlockedServiceID(s string) (id BlockedServiceID, err error) {
	return internal.NewBlockedServiceID(s)
}

// HashMatcher is the interface for a safe-browsing and adult-blocking hash
// matcher, which is used to respond to a TXT query based on the domain name.
type HashMatcher interface {
	MatchByPrefix(ctx context.Context, host string) (hashes []string, matched bool, err error)
}

// Default safe-browsing host suffixes.
const (
	GeneralTXTSuffix       = ".sb.dns.adguard.com"
	AdultBlockingTXTSuffix = ".pc.dns.adguard.com"
)

// Metrics is the interface for metrics of filters.
type Metrics = internal.Metrics

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics = internal.EmptyMetrics
