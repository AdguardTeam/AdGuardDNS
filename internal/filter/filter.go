// Package filter contains the filter interface and its implementations along
// with types that combine them based on the settings in profile and filtering
// group.
package filter

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/c2h5oh/datasize"
	"github.com/miekg/dns"
)

// Common Constants, Functions, and Types

// maxFilterSize is the maximum size of downloaded filters.
const maxFilterSize = 196 * int64(datasize.MB)

// defaultTimeout is the default timeout to use when fetching filter data.
//
// TODO(a.garipov): Consider making timeouts where they are used configurable.
const defaultTimeout = 30 * time.Second

// defaultResolveTimeout is the default timeout for resolving hosts for safe
// search and safe browsing filters.
//
// TODO(ameshkov): Consider making configurable.
const defaultResolveTimeout = 1 * time.Second

// Interface is the DNS request and response filter interface.
type Interface interface {
	// FilterRequest filters the DNS request for the provided client.  All
	// parameters must be non-nil.  req must have exactly one question.  If a is
	// nil, the request doesn't match any of the rules.
	FilterRequest(ctx context.Context, req *dns.Msg, ri *agd.RequestInfo) (r Result, err error)

	// FilterResponse filters the DNS response for the provided client.  All
	// parameters must be non-nil.  If a is nil, the response doesn't match any
	// of the rules.
	FilterResponse(ctx context.Context, resp *dns.Msg, ri *agd.RequestInfo) (r Result, err error)

	// Close closes the filter and frees resources associated with it.
	Close() (err error)
}

// Filtering Result Aliases

// Result is a sum type of all possible filtering actions.  See the following
// types as implementations:
//
//   - [*ResultAllowed]
//   - [*ResultBlocked]
//   - [*ResultModified]
type Result = internal.Result

// ResultAllowed means that this request or response was allowed by an allowlist
// rule within the given filter list.
type ResultAllowed = internal.ResultAllowed

// ResultBlocked means that this request or response was blocked by a blocklist
// rule within the given filter list.
type ResultBlocked = internal.ResultBlocked

// ResultModified means that this request or response was rewritten or modified
// by a rewrite rule within the given filter list.
type ResultModified = internal.ResultModified
