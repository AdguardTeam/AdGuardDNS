package dnsserver

import "github.com/miekg/dns"

// Disposer is an interface for pools that can save parts of DNS response
// messages for later reuse.
//
// TODO(a.garipov): Think of ways of extending [ResponseWriter] to do this
// instead.
//
// TODO(a.garipov): Think of a better name.  Recycle?  Scrap?
type Disposer interface {
	// Dispose saves parts of resp for later reuse.  resp may be nil.
	// Implementations must be safe for concurrent use.
	Dispose(resp *dns.Msg)
}

// EmptyDisposer is a [Disposer] that does nothing.
type EmptyDisposer struct{}

// type check
var _ Disposer = EmptyDisposer{}

// Dispose implements the [Disposer] interface for EmptyDisposer.
func (EmptyDisposer) Dispose(_ *dns.Msg) {}
