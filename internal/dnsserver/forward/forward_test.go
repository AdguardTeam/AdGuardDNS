package forward_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

func TestHandler_ServeDNS(t *testing.T) {
	srv, addr := dnsservertest.RunDNSServer(t, dnsservertest.DefaultHandler())

	// No-fallbacks handler.
	handler := forward.NewHandler(&forward.HandlerConfig{
		Address: netip.MustParseAddrPort(addr),
		Network: forward.NetworkAny,
	}, true)

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	rw := dnsserver.NewNonWriterResponseWriter(srv.LocalUDPAddr(), srv.LocalUDPAddr())

	// Check the handler's ServeDNS method
	err := handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)

	res := rw.Msg()
	require.NotNil(t, res)
	dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)
}

func TestHandler_ServeDNS_fallbackNetError(t *testing.T) {
	srv, _ := dnsservertest.RunDNSServer(t, dnsservertest.DefaultHandler())
	handler := forward.NewHandler(&forward.HandlerConfig{
		Address: netip.MustParseAddrPort("127.0.0.1:0"),
		Network: forward.NetworkAny,
		FallbackAddresses: []netip.AddrPort{
			netip.MustParseAddrPort(srv.LocalUDPAddr().String()),
		},
	}, true)

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	rw := dnsserver.NewNonWriterResponseWriter(srv.LocalUDPAddr(), srv.LocalUDPAddr())

	// Check the handler's ServeDNS method
	err := handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)

	res := rw.Msg()
	require.NotNil(t, res)
	dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)
}
