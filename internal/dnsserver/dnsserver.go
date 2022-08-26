// Copyright (C) 2022 AdGuard Software Ltd.
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, version 3.

package dnsserver

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

// Handler is an interface that defines how the DNS server would process DNS
// queries. Inspired by net/http.Server and it's Handler.
type Handler interface {
	// ServeDNS should process the request and write a DNS response to the
	// specified ResponseWriter.
	//
	// It accepts context.Context argument which has some additional info
	// attached to it. This context always contains ServerInfo which can be
	// retrieved using ServerInfoFromContext or MustServerInfoFromContext.
	// Also, it always contains request's start time that can be retrieved
	// using StartTimeFromContext.
	ServeDNS(context.Context, ResponseWriter, *dns.Msg) error
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions
// as DNS handlers. If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler that calls f.
type HandlerFunc func(context.Context, ResponseWriter, *dns.Msg) error

// ServeDNS implements the Handler interface for HandlerFunc.
func (f HandlerFunc) ServeDNS(ctx context.Context, rw ResponseWriter, req *dns.Msg) (err error) {
	return f(ctx, rw, req)
}

// notImplementedHandlerFunc is used if no Handler is configured for a server.
var notImplementedHandlerFunc HandlerFunc = func(
	ctx context.Context,
	w ResponseWriter,
	r *dns.Msg,
) (err error) {
	res := new(dns.Msg)
	res.SetRcode(r, dns.RcodeNotImplemented)

	return w.WriteMsg(ctx, r, res)
}

// Server represents a DNS server.
type Server interface {
	// Start starts the server, exits immediately if it failed to start
	// listening.  Start returns once all servers are considered up.
	Start(ctx context.Context) (err error)
	// Shutdown stops the server and waits for all active connections to close.
	Shutdown(ctx context.Context) (err error)
	// LocalAddr returns the address the server listens to at the moment.  It
	// must be safe for concurrent use.
	LocalAddr() (lAddr net.Addr)
}

// A ResponseWriter interface is used by a DNS handler to construct a DNS
// response.
type ResponseWriter interface {
	// LocalAddr returns the net.Addr of the server.
	LocalAddr() net.Addr

	// RemoteAddr returns the net.Addr of the client that sent the current
	// request.
	RemoteAddr() net.Addr

	// WriteMsg writes a reply back to the client.
	//
	// Handlers must not modify req and resp after the call to WriteMsg, since
	// their ResponseWriter implementation may be a recorder.
	WriteMsg(ctx context.Context, req, resp *dns.Msg) error
}
