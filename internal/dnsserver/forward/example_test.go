package forward_test

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

func ExampleNewHandler() {
	conf := &dnsserver.ConfigDNS{
		Base: &dnsserver.ConfigBase{
			BaseLogger: slogutil.NewDiscardLogger(),
			Name:       "srv",
			Addr:       "127.0.0.1:0",
			Handler: forward.NewHandler(&forward.HandlerConfig{
				UpstreamsAddresses: []*forward.UpstreamPlainConfig{{
					Network: forward.NetworkAny,
					Address: netip.MustParseAddrPort("8.8.8.8:53"),
					Timeout: testTimeout,
				}},
				FallbackAddresses: []*forward.UpstreamPlainConfig{{
					Network: forward.NetworkAny,
					Address: netip.MustParseAddrPort("1.1.1.1:53"),
					Timeout: testTimeout,
				}},
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
