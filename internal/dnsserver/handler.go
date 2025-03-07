package dnsserver

import (
	"context"

	"github.com/miekg/dns"
)

// Handler is an interface that defines how the DNS server would process DNS
// queries.  Inspired by net/http.Server and it's Handler.
type Handler interface {
	// ServeDNS processes the request and writes a DNS response to rw.  ctx must
	// contain [*ServerInfo] and [*RequestInfo].  rw and req must not be nil.
	// req must have exactly one question.
	ServeDNS(ctx context.Context, rw ResponseWriter, req *dns.Msg) (err error)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions
// as DNS handlers.  If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler that calls f.
type HandlerFunc func(context.Context, ResponseWriter, *dns.Msg) (err error)

// type check
var _ Handler = HandlerFunc(nil)

// ServeDNS implements the [Handler] interface for HandlerFunc.
func (f HandlerFunc) ServeDNS(ctx context.Context, rw ResponseWriter, req *dns.Msg) (err error) {
	return f(ctx, rw, req)
}

// notImplementedHandlerFunc is used if no Handler is configured for a server.
var notImplementedHandlerFunc HandlerFunc = func(
	ctx context.Context,
	w ResponseWriter,
	r *dns.Msg,
) (err error) {
	res := (&dns.Msg{}).SetRcode(r, dns.RcodeNotImplemented)

	return w.WriteMsg(ctx, r, res)
}
