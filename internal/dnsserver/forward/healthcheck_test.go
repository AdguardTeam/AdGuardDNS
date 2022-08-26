package forward_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_Refresh(t *testing.T) {
	var upstreamUp uint64
	var upstreamRequestsCount uint64

	// This handler writes an empty message if upstreamUp flag is false.
	handlerFunc := dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		req *dns.Msg,
	) (err error) {
		atomic.AddUint64(&upstreamRequestsCount, 1)

		nrw := dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
		handler := dnsservertest.DefaultHandler()
		err = handler.ServeDNS(ctx, nrw, req)
		if err != nil {
			return err
		}

		if atomic.LoadUint64(&upstreamUp) == 0 {
			return rw.WriteMsg(ctx, req, &dns.Msg{})
		}

		return rw.WriteMsg(ctx, req, nrw.Msg())
	})

	upstream, err := dnsservertest.RunDNSServer(handlerFunc)
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return upstream.Shutdown(context.Background())
	})

	fallback, err := dnsservertest.RunDNSServer(dnsservertest.DefaultHandler())
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return fallback.Shutdown(context.Background())
	})

	handler := forward.NewHandler(&forward.HandlerConfig{
		Address:               netip.MustParseAddrPort(upstream.Addr),
		HealthcheckDomainTmpl: "${RANDOM}.upstream-check.example",
		FallbackAddresses: []netip.AddrPort{
			netip.MustParseAddrPort(fallback.Addr),
		},
		// Make sure that the handler routs queries back to the main upstream
		// immediately.
		HealthcheckBackoffDuration: 0,
	}, false)

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	addr := fallback.SrvTCP.LocalAddr()
	rw := dnsserver.NewNonWriterResponseWriter(addr, addr)

	err = handler.ServeDNS(context.Background(), rw, req)
	require.Error(t, err)
	assert.Equal(t, uint64(1), atomic.LoadUint64(&upstreamRequestsCount))

	err = handler.Refresh(context.Background())
	require.Error(t, err)
	assert.Equal(t, uint64(2), atomic.LoadUint64(&upstreamRequestsCount))

	err = handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), atomic.LoadUint64(&upstreamRequestsCount))

	// Now, set upstream up.
	atomic.StoreUint64(&upstreamUp, 1)

	err = handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), atomic.LoadUint64(&upstreamRequestsCount))

	err = handler.Refresh(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(3), atomic.LoadUint64(&upstreamRequestsCount))

	err = handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)
	assert.Equal(t, uint64(4), atomic.LoadUint64(&upstreamRequestsCount))
}
