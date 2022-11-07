package forward_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
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

	upstream, _ := dnsservertest.RunDNSServer(t, handlerFunc)
	fallback, _ := dnsservertest.RunDNSServer(t, dnsservertest.DefaultHandler())
	handler := forward.NewHandler(&forward.HandlerConfig{
		Address:               netip.MustParseAddrPort(upstream.LocalUDPAddr().String()),
		Network:               forward.NetworkAny,
		HealthcheckDomainTmpl: "${RANDOM}.upstream-check.example",
		FallbackAddresses: []netip.AddrPort{
			netip.MustParseAddrPort(fallback.LocalUDPAddr().String()),
		},
		// Make sure that the handler routs queries back to the main upstream
		// immediately.
		HealthcheckBackoffDuration: 0,
	}, false)

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	rw := dnsserver.NewNonWriterResponseWriter(fallback.LocalUDPAddr(), fallback.LocalUDPAddr())

	err := handler.ServeDNS(context.Background(), rw, req)
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
