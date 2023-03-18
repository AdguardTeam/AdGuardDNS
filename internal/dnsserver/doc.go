// Copyright (C) 2022-2023 AdGuard Software Ltd.
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, version 3.

/*
Package dnsserver implements server-side of all popular DNS protocols:

  - Plain DNS
  - DNS-over-TLS
  - DNS-over-HTTPS
  - DNS-over-QUIC
  - DNSCrypt

The dnsserver package is responsible for accepting the DNS queries and writing
the response to the client and properly normalizing it.  It does not contain any
recursor or forwarding functionality, it needs to be implemented elsewhere.

All servers implement the dnsserver.Server interface which provides basic
functionality.

# Handlers

You need to pass a [dnsserver.Handler] to the server constructor. Here is an
example of a simple handler function that forwards queries to AdGuard DNS:

	handler := dnsserver.HandlerFunc(
		func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
			// Forward the request to AdGuard DNS.
			res, err := dns.Exchange(req, "94.140.14.140")
			if err != nil {
				// The server writes a SERVFAIL response if a handler returns an
				// error.
				return err
			}

			return rw.WriteMsg(ctx, req, res)
		},
	)

Alternatively, you can use forward.NewHandler to create a DNS forwarding handler
(see below).

# Plain DNS

By default, plain DNS server will listen to both TCP and UDP unless Network
is specified in the configuration.  Here's how to create a simple plain
DNS server:

	conf := dnsserver.ConfigDNS{
		ConfigBase: dnsserver.ConfigBase{
			// server name
			Name: "test",
			// listen address
			Addr: "127.0.0.1:0",
			// handler that will process incoming DNS queries
			Handler: handler,
		},
	}
	srv := dnsserver.NewServerDNS(conf)
	err := srv.Start(context.Background())

Normally, you would like to run two servers on the same address.  One would
listen to TCP, and the other one would listen to UDP.

# DNS-over-TLS

In order to use a DoT server, you also need to supply a [*tls.Config] with the
certificate and its private key.

	conf := dnsserver.ConfigTLS{
		ConfigDNS: dnsserver.ConfigDNS{
			ConfigBase: dnsserver.ConfigBase{
				Name:    "test",
				Addr:    "127.0.0.1:0",
				Handler: h,
			},
		},
		TLSConfig: tlsConfig,
	}
	s = dnsserver.NewServerTLS(conf)
	err := s.Start(context.Background())

# DNS-over-HTTPS

DoH server uses an [*http.Server] and/or [*http3.Server] internally. There are
a couple of things to note:

 1. tls.Config can be omitted, but you must set [ConfigBase.Network] to
    NetworkTCP.  In this case the server will work simply as a plain HTTP
    server. This might be useful if you're running a reverse proxy like Nginx
    in front of your DoH server.  If you do specify it, the server will listen
    to both DoH2 and DoH3 by default.

 2. In the constructor you can specify an optional [http.HandlerFunc] that
    processes non-DNS requests, e.g. requests to paths different from
    "/dns-query" and "/resolve".

Example:

	conf := dnsserver.ConfigHTTPS{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Handler: h,
		},
		TLSConfig:     tlsConfig,
		NonDNSHandler: nonDNSHandler,
	}
	s = dnsserver.NewServerHTTPS(conf)
	err := s.Start(context.Background())

# DNS-over-QUIC

DoQ server uses the [quic-go module].  Just like DoH and DoT, it requires a
[*tls.Config] to encrypt the data.

	conf := dnsserver.ConfigQUIC{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Handler: h,
		},
		TLSConfig: tlsConfig,
	}
	s = dnsserver.NewServerQUIC(conf)
	err := s.Start(context.Background())

# DNSCrypt

DNSCrypt servers use the [dnscrypt module] module.  In order to run a DNSCrypt
server you need to supply DNSCrypt configuration.  Read the [module
documentation] about how to initialize it.

	conf := dnsserver.ConfigDNSCrypt{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Handler: h,
		},
		DNSCryptProviderName: s.ProviderName,
		DNSCryptResolverCert: cert,
	}
	s := dnsserver.NewServerDNSCrypt(conf)
	err := s.Start(context.Background())

# Middlewares

Package dnsserver supports customizing server behavior using middlewares.  All
you need to do is implement dnsserver.Middleware interface and use it this way:

	forwarder := forward.NewHandler(&forward.HandlerConfig{
		Address: netip.MustParseAddrPort("94.140.14.140:53"),
	})
	middleware := querylog.NewLogMiddleware(os.Stdout)
	handler := dnsserver.WithMiddlewares(forwarder, middleware)

After that you can use the resulting handler when creating server instances.

# Metrics And Error Reporting

Package dnsserver allows you to register custom listeners which would be called
in case a DNS request was processed or if an error occurred.  In order to use
them, you need to implement the [dnsserver.MetricsListener] interface and set it
in the server configuration.  For instance, you can use
[prometheus.ServerMetricsListener] to make it record prometheus metrics.

[quic-go module]: https://github.com/quic-go/quic-go
[dnscrypt module]: https://github.com/ameshkov/dnscrypt
[module documentation]: https://github.com/ameshkov/dnscrypt#server
*/
package dnsserver
