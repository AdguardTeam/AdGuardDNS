// Package internal contains common constants, types, and utilities shared by
// other subpackages of package filter/.
//
// TODO(a.garipov):  Merge into package filter.
package internal

import (
	"context"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/miekg/dns"
)

// Interface is the DNS request and response filter interface.
type Interface interface {
	// FilterRequest filters a DNS request based on the information provided
	// about the request.  req must be valid.
	FilterRequest(ctx context.Context, req *Request) (r Result, err error)

	// FilterResponse filters a DNS response based on the information provided
	// about the response.  resp must be valid.
	FilterResponse(ctx context.Context, resp *Response) (r Result, err error)
}

// Request contains information about a request being filtered.
type Request struct {
	// DNS is the original DNS request used to create filtered responses.  It
	// must not be nil and must have exactly one question.
	DNS *dns.Msg

	// Messages is used to create filtered responses for this request.  It must
	// not be nil.
	Messages *dnsmsg.Constructor

	// RemoteIP is the remote IP address of the client.
	RemoteIP netip.Addr

	// ClientName is the client name for rule-list filtering.
	ClientName string

	// Host is the lowercased, non-FQDN version of the hostname from the
	// question of the request.
	Host string

	// QType is the type of question for this request.
	QType dnsmsg.RRType

	// QClass is the class of question for this request.
	QClass dnsmsg.Class
}

// Response contains information about a response being filtered.
type Response struct {
	// DNS is the original DNS response used to create filtered responses.  It
	// must not be nil and must have exactly one question.
	DNS *dns.Msg

	// RemoteIP is the remote IP address of the client.
	RemoteIP netip.Addr

	// ClientName is the client name for rule-list filtering.
	ClientName string
}

// Empty is an [Interface] implementation that always returns nil.
type Empty struct{}

// type check
var _ Interface = Empty{}

// FilterRequest implements the [Interface] interface for Empty.
func (Empty) FilterRequest(_ context.Context, _ *Request) (r Result, err error) {
	return nil, nil
}

// FilterResponse implements the [Interface] interface for Empty.
func (Empty) FilterResponse(_ context.Context, _ *Response) (r Result, err error) {
	return nil, nil
}

// DefaultResolveTimeout is the default timeout for resolving hosts for
// safe-search and safe-browsing filters.
//
// TODO(ameshkov): Consider making configurable.
const DefaultResolveTimeout = 1 * time.Second

// RequestFilter can filter a request based on the request info.
type RequestFilter interface {
	FilterRequest(ctx context.Context, req *Request) (r Result, err error)
	ID() (id ID)
}

// ConfigCustom is the configuration for identification or construction of a
// custom filter for a client.
type ConfigCustom struct {
	// ID is the unique ID for this custom filter.
	ID string

	// UpdateTime is the last time this configuration has been updated.
	UpdateTime time.Time

	// Rules are the filtering rules for this configuration.
	Rules []RuleText

	// Enabled shows whether the custom filters are applied at all.
	Enabled bool
}
