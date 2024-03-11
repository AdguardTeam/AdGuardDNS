// Package internal contains common constants, types, and utilities shared by
// other subpackages of package filter/.
package internal

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/miekg/dns"
)

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
}

// DefaultFilterRefreshTimeout is the default timeout to use when fetching
// filter lists data.
const DefaultFilterRefreshTimeout = 3 * time.Minute

// DefaultResolveTimeout is the default timeout for resolving hosts for
// safe-search and safe-browsing filters.
//
// TODO(ameshkov): Consider making configurable.
const DefaultResolveTimeout = 1 * time.Second

// RequestFilter can filter a request based on the request info.
type RequestFilter interface {
	FilterRequest(ctx context.Context, req *dns.Msg, ri *agd.RequestInfo) (r Result, err error)
	ID() (id agd.FilterListID)
}
