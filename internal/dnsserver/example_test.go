package dnsserver_test

import (
	"context"
	"log/slog"
	"net/netip"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/querylog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
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

	baseLogger := slogutil.New(&slogutil.Config{
		Format: slogutil.FormatText,
		Level:  slog.LevelDebug,
	}).With("server_name", "test")

	// Init the server with this handler func
	conf := &dnsserver.ConfigDNS{
		Base: &dnsserver.ConfigBase{
			BaseLogger: baseLogger,

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

	// Unordered output:
	// level=INFO msg="starting server" server_name=test
	// level=INFO msg="server has been started" server_name=test
	// level=INFO msg="shutting down server" server_name=test
	// level=INFO msg="starting listening udp" server_name=test
	// level=INFO msg="starting listening tcp" server_name=test
	// level=INFO msg="server has been shut down" server_name=test
}

func ExampleWithMiddlewares() {
	// Init a handler func function with middlewares.
	forwarder := forward.NewHandler(&forward.HandlerConfig{
		UpstreamsAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort("94.140.14.140:53"),
		}},
	})

	baseLogger := slogutil.New(&slogutil.Config{
		Format: slogutil.FormatText,
		Level:  slog.LevelDebug,
	})

	middleware := querylog.NewLogMiddleware(os.Stdout, baseLogger)
	handler := dnsserver.WithMiddlewares(forwarder, middleware)

	// Init the server with this handler func.
	conf := &dnsserver.ConfigDNS{
		Base: &dnsserver.ConfigBase{
			BaseLogger: baseLogger.With("server_name", "test"),
			Name:       "test",
			Addr:       "127.0.0.1:0",
			Handler:    handler,
		},
	}
	srv := dnsserver.NewServerDNS(conf)

	ctx := context.Background()
	err := srv.Start(ctx)
	if err != nil {
		panic("failed to start the server")
	}

	baseLogger.InfoContext(ctx, "started successfully")

	defer func() {
		err = srv.Shutdown(context.Background())
		if err != nil {
			panic("failed to shutdown the server")
		}

		baseLogger.InfoContext(ctx, "stopped successfully")
	}()

	// Unordered output:
	// level=INFO msg="starting server" server_name=test
	// level=INFO msg="server has been started" server_name=test
	// level=INFO msg="started successfully"
	// level=INFO msg="shutting down server" server_name=test
	// level=INFO msg="starting listening udp" server_name=test
	// level=INFO msg="starting listening tcp" server_name=test
	// level=INFO msg="server has been shut down" server_name=test
	// level=INFO msg="stopped successfully"
}
