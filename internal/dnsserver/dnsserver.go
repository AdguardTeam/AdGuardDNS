// Copyright (C) 2022-2024 AdGuard Software Ltd.
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, version 3.

package dnsserver

import (
	"context"
	"net"
)

// Server represents a DNS server.
//
// TODO(a.garipov):  Minimize the number of methods; consider embedding
// service.Service from golibs.
type Server interface {
	// Name returns the server name.
	//
	// TODO(a.garipov):  Consider removing.
	Name() (name string)

	// Proto returns the protocol of the server.
	//
	// TODO(a.garipov):  Consider removing.
	Proto() (proto Protocol)

	// Network is a network (tcp, udp or empty) this server listens to.  If it
	// is empty, the server listens to all networks that are supposed to be
	// used by its protocol.
	//
	// TODO(a.garipov):  Consider removing.
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

	// LocalUDPAddr returns the UDP address the server listens to at the moment
	// or nil if it does not listen to UDP.  Depending on the server protocol it
	// may correspond to DNS-over-UDP, HTTP3, QUIC, DNSCrypt (UDP).
	LocalUDPAddr() (addr net.Addr)
}
