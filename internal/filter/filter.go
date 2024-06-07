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

// Filtering result aliases

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

// Hash matching for safe-browsing and adult-content blocking

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
