package forward_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// testTimeout is the timeout for tests.
const testTimeout = 1 * time.Second

func TestHandler_ServeDNS(t *testing.T) {
	srv, addr := dnsservertest.RunDNSServer(t, dnsservertest.NewDefaultHandler())

	// No-fallbacks handler.
	handler := forward.NewHandler(&forward.HandlerConfig{
		Logger: slogutil.NewDiscardLogger(),
		UpstreamsAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort(addr),
			Timeout: testTimeout,
		}},
	})

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	rw := dnsserver.NewNonWriterResponseWriter(srv.LocalUDPAddr(), srv.LocalUDPAddr())

	// Check the handler's ServeDNS method
	err := handler.ServeDNS(testutil.ContextWithTimeout(t, testTimeout), rw, req)
	require.NoError(t, err)

	dnsservertest.RequireResponse(t, req, rw.Msg(), 1, dns.RcodeSuccess, false)
}

func TestHandler_ServeDNS_fallbackNetError(t *testing.T) {
	srv, _ := dnsservertest.RunDNSServer(t, dnsservertest.NewDefaultHandler())
	handler := forward.NewHandler(&forward.HandlerConfig{
		Logger: slogutil.NewDiscardLogger(),
		UpstreamsAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort("127.0.0.1:0"),
			Timeout: testTimeout,
		}},
		FallbackAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort(srv.LocalUDPAddr().String()),
			Timeout: testTimeout,
		}},
	})

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	rw := dnsserver.NewNonWriterResponseWriter(srv.LocalUDPAddr(), srv.LocalUDPAddr())

	// Check the handler's ServeDNS method
	err := handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)

	dnsservertest.RequireResponse(t, req, rw.Msg(), 1, dns.RcodeSuccess, false)
}
