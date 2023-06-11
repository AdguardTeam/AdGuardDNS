package forward_test

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
)

func ExampleNewHandler() {
	conf := dnsserver.ConfigDNS{
		ConfigBase: dnsserver.ConfigBase{
			Name: "srv",
			Addr: "127.0.0.1:0",
			Handler: forward.NewHandler(&forward.HandlerConfig{
				Address: netip.MustParseAddrPort("8.8.8.8:53"),
				Network: forward.NetworkAny,
				FallbackAddresses: []netip.AddrPort{
					netip.MustParseAddrPort("1.1.1.1:53"),
				},
			}),
		},
	}

	srv := dnsserver.NewServerDNS(conf)
	err := srv.Start(context.Background())
	if err != nil {
		panic("failed to start the server")
	}

	fmt.Println("started server")

	defer func() {
		err = srv.Shutdown(context.Background())
		if err != nil {
			panic("failed to shutdown the server")
		}

		fmt.Println("stopped server")
	}()

	// Output:
	//
	// started server
	// stopped server
}
