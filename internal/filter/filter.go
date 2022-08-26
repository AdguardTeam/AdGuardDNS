// Package filter contains the filter interface and its implementations along
// with types that combine them based on the settings in profile and filtering
// group.
package filter

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/c2h5oh/datasize"
	"github.com/miekg/dns"
)

// Common Constants, Functions, and Types

// maxFilterSize is the maximum size of downloaded filters.
const maxFilterSize = 128 * int64(datasize.MB)

// defaultTimeout is the default timeout to use when fetching filter data.
//
// TODO(a.garipov): Consider making timeouts where they are used configurable.
const defaultTimeout = 30 * time.Second

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

// Network constants.
const (
	netIP4 = "ip4"
	netIP6 = "ip6"
)

// dnsTypeToNetwork converts a DNS RR type to a network type.  If rr is neither
// A nor AAAA, network is an empty string.
func dnsTypeToNetwork(qt dnsmsg.RRType) (network string) {
	switch qt {
	case dns.TypeA:
		return netIP4
	case dns.TypeAAAA:
		return netIP6
	default:
		return ""
	}
}
