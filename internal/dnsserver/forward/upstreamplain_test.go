package forward_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestUpstreamPlain_Exchange(t *testing.T) {
	testCases := []struct {
		name    string
		network forward.Network
	}{{
		name:    "any",
		network: forward.NetworkAny,
	}, {
		name:    "udp",
		network: forward.NetworkUDP,
	}, {
		name:    "tcp",
		network: forward.NetworkTCP,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, addr := dnsservertest.RunDNSServer(t, dnsservertest.DefaultHandler())
			u := forward.NewUpstreamPlain(netip.MustParseAddrPort(addr), tc.network)
			defer log.OnCloserError(u, log.DEBUG)

			req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
			res, err := u.Exchange(context.Background(), req)
			require.NoError(t, err)
			require.NotNil(t, res)
			dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)
		})
	}
}

func TestUpstreamPlain_Exchange_truncated(t *testing.T) {
	// this handler always truncates responses if they're received over UDP.
	handlerFunc := dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		req *dns.Msg,
	) (err error) {
		nrw := dnsserver.NewNonWriterResponseWriter(
			rw.LocalAddr(),
			rw.RemoteAddr(),
		)
		handler := dnsservertest.DefaultHandler()
		err = handler.ServeDNS(ctx, nrw, req)
		if err != nil {
			return err
		}

		res := nrw.Msg()
		network := dnsserver.NetworkFromAddr(rw.LocalAddr())

		if network == dnsserver.NetworkUDP {
			res.Truncated = true
			res.Answer = nil
		}

		return rw.WriteMsg(ctx, req, res)
	})

	_, addr := dnsservertest.RunDNSServer(t, handlerFunc)

	// Create a test message.
	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)

	// First, check that we receive truncated response over UDP.
	uAddr := netip.MustParseAddrPort(addr)
	uUDP := forward.NewUpstreamPlain(uAddr, forward.NetworkUDP)
	defer log.OnCloserError(uUDP, log.DEBUG)

	res, err := uUDP.Exchange(context.Background(), req)
	require.NoError(t, err)
	dnsservertest.RequireResponse(t, req, res, 0, dns.RcodeSuccess, true)

	// Second, check that nothing is truncated over TCP.
	uTCP := forward.NewUpstreamPlain(uAddr, forward.NetworkTCP)
	defer log.OnCloserError(uTCP, log.DEBUG)

	res, err = uTCP.Exchange(context.Background(), req)
	require.NoError(t, err)
	dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)

	// Now with NetworkANY response is also not truncated since the upstream
	// fallbacks to TCP.
	uAny := forward.NewUpstreamPlain(uAddr, forward.NetworkAny)
	defer log.OnCloserError(uAny, log.DEBUG)

	res, err = uAny.Exchange(context.Background(), req)
	require.NoError(t, err)
	dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)
}
