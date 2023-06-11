package dnsserver_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/querylog"
	"github.com/miekg/dns"
)

func ExampleNewServerDNS() {
	// Create a DNS handler
	handler := dnsserver.HandlerFunc(
		func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
			// forward the request to AdGuard DNS
			res, err := dns.Exchange(req, "94.140.14.140")
			if err != nil {
				// the server will write a SERVFAIL response if handler
				// returns an error
				return err
			}
			return rw.WriteMsg(ctx, req, res)
		},
	)

	// Init the server with this handler func
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
	if err != nil {
		panic("failed to start the server")
	}

	defer func() {
		err = srv.Shutdown(context.Background())
		if err != nil {
			panic("failed to shutdown the server")
		}
	}()

	// Output:
}

func ExampleWithMiddlewares() {
	// Init a handler func function with middlewares.
	forwarder := forward.NewHandler(&forward.HandlerConfig{
		Address: netip.MustParseAddrPort("94.140.14.140:53"),
		Network: forward.NetworkAny,
	})

	middleware := querylog.NewLogMiddleware(os.Stdout)
	handler := dnsserver.WithMiddlewares(forwarder, middleware)

	// Init the server with this handler func
	conf := dnsserver.ConfigDNS{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Handler: handler,
		},
	}
	srv := dnsserver.NewServerDNS(conf)
	err := srv.Start(context.Background())
	if err != nil {
		panic("failed to start the server")
	}

	fmt.Println("started successfully")

	defer func() {
		err = srv.Shutdown(context.Background())
		if err != nil {
			panic("failed to shutdown the server")
		}

		fmt.Println("stopped successfully")
	}()

	// Output:
	// started successfully
	// stopped successfully
}
