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
	dnsservertest.DiscardLogOutput(m)
}

func TestHandler_ServeDNS(t *testing.T) {
	srv, err := dnsservertest.RunDNSServer(dnsservertest.DefaultHandler())
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// No-fallbacks handler.
	handler := forward.NewHandler(&forward.HandlerConfig{
		Address: netip.MustParseAddrPort(srv.Addr),
	}, true)

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	addr := srv.SrvTCP.LocalAddr()
	rw := dnsserver.NewNonWriterResponseWriter(addr, addr)

	// Check the handler's ServeDNS method
	err = handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)

	res := rw.Msg()
	require.NotNil(t, res)
	dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)
}

func TestHandler_ServeDNS_fallbackNetError(t *testing.T) {
	srv, err := dnsservertest.RunDNSServer(dnsservertest.DefaultHandler())
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	handler := forward.NewHandler(&forward.HandlerConfig{
		Address: netip.MustParseAddrPort("127.0.0.1:0"),
		FallbackAddresses: []netip.AddrPort{
			netip.MustParseAddrPort(srv.Addr),
		},
	}, true)

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	addr := srv.SrvTCP.LocalAddr()
	rw := dnsserver.NewNonWriterResponseWriter(addr, addr)

	// Check the handler's ServeDNS method
	err = handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)

	res := rw.Msg()
	require.NotNil(t, res)
	dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)
}
