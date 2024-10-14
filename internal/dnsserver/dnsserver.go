// Copyright (C) 2022-2024 AdGuard Software Ltd.
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
// queries.  Inspired by net/http.Server and it's Handler.
type Handler interface {
	// ServeDNS should process the request and write a DNS response to the
	// specified ResponseWriter.
	//
	// It accepts context.Context argument which has some additional info
	// attached to it.  This context always contains [ServerInfo] which can be
	// retrieved using [ServerInfoFromContext] or [MustServerInfoFromContext].
	// It also must contain [RequestInfo] that can be retrieved with
	// [RequestInfoFromContext] or [MustRequestInfoFromContext].
	ServeDNS(context.Context, ResponseWriter, *dns.Msg) (err error)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions
// as DNS handlers.  If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler that calls f.
type HandlerFunc func(context.Context, ResponseWriter, *dns.Msg) (err error)

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
//
// TODO(ameshkov): move validation to ctors (for all structs that inherit this).
//
// TODO(ameshkov): consider Proto()/Network()/Addr() -> single Info() func.
type Server interface {
	// Name returns the server name.
	Name() (name string)
	// Proto returns the protocol of the server.
	Proto() (proto Protocol)
	// Network is a network (tcp, udp or empty) this server listens to.  If it
	// is empty, the server listens to all networks that are supposed to be
	// used by its protocol.
	Network() (network Network)
	// Addr returns the address the server was configured to listen to.
	Addr() (addr string)
	// Start starts the server, exits immediately if it failed to start
	// listening.  Start returns once all servers are considered up.
	Start(ctx context.Context) (err error)
	// Shutdown stops the server and waits for all active connections to close.
	Shutdown(ctx context.Context) (err error)
	// LocalTCPAddr returns the TCP address the server listens to at the moment
	// or nil if it does not listen to TCP.  Depending on the server protocol
	// it may correspond to DNS-over-TCP, DNS-over-TLS, HTTP2, DNSCrypt (TCP).
	LocalTCPAddr() (addr net.Addr)
	// LocalUDPAddr returns the UDP address the server listens to at the moment or
	// nil if it does not listen to UDP.  Depending on the server protocol
	// it may correspond to DNS-over-UDP, HTTP3, QUIC, DNSCrypt (UDP).
	LocalUDPAddr() (addr net.Addr)
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
	//
	// TODO(a.garipov): Store bytes written to the socket.
	WriteMsg(ctx context.Context, req, resp *dns.Msg) error
}
