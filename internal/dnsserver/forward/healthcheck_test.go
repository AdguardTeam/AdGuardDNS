package forward_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_Refresh(t *testing.T) {
	var upstreamIsUp atomic.Bool
	var upstreamRequestsCount atomic.Int64

	defaultHandler := dnsservertest.NewDefaultHandler()

	// This handler writes an empty message if upstreamUp flag is false.
	handlerFunc := dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		req *dns.Msg,
	) (err error) {
		upstreamRequestsCount.Add(1)

		nrw := dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
		err = defaultHandler.ServeDNS(ctx, nrw, req)
		if err != nil {
			return err
		}

		if !upstreamIsUp.Load() {
			return rw.WriteMsg(ctx, req, &dns.Msg{})
		}

		return rw.WriteMsg(ctx, req, nrw.Msg())
	})

	upstream, _ := dnsservertest.RunDNSServer(t, handlerFunc)
	fallback, _ := dnsservertest.RunDNSServer(t, defaultHandler)
	handler := forward.NewHandler(&forward.HandlerConfig{
		Logger: slogutil.NewDiscardLogger(),
		UpstreamsAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort(upstream.LocalUDPAddr().String()),
			Timeout: testTimeout,
		}},
		HealthcheckDomainTmpl: "${RANDOM}.upstream-check.example",
		FallbackAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort(fallback.LocalUDPAddr().String()),
			Timeout: testTimeout,
		}},
		// Make sure that the handler routes queries back to the main upstream
		// immediately.
		HealthcheckBackoffDuration: 0,
	})

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	rw := dnsserver.NewNonWriterResponseWriter(fallback.LocalUDPAddr(), fallback.LocalUDPAddr())

	err := handler.ServeDNS(testutil.ContextWithTimeout(t, testTimeout), rw, req)
	require.Error(t, err)
	assert.Equal(t, int64(2), upstreamRequestsCount.Load())

	err = handler.Refresh(testutil.ContextWithTimeout(t, testTimeout))
	require.Error(t, err)
	assert.Equal(t, int64(4), upstreamRequestsCount.Load())

	err = handler.ServeDNS(testutil.ContextWithTimeout(t, testTimeout), rw, req)
	require.NoError(t, err)
	assert.Equal(t, int64(4), upstreamRequestsCount.Load())

	// Now, set upstream up.
	upstreamIsUp.Store(true)

	err = handler.ServeDNS(testutil.ContextWithTimeout(t, testTimeout), rw, req)
	require.NoError(t, err)
	assert.Equal(t, int64(4), upstreamRequestsCount.Load())

	err = handler.Refresh(testutil.ContextWithTimeout(t, testTimeout))
	require.NoError(t, err)
	assert.Equal(t, int64(5), upstreamRequestsCount.Load())

	err = handler.ServeDNS(testutil.ContextWithTimeout(t, testTimeout), rw, req)
	require.NoError(t, err)
	assert.Equal(t, int64(6), upstreamRequestsCount.Load())
}
