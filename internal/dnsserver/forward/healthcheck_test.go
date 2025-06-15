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
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_Refresh_healthcheck(t *testing.T) {
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
		Healthcheck: &forward.HealthcheckConfig{
			Enabled:         true,
			DomainTempalate: "${RANDOM}.upstream-check.example",
			// Make sure that the handler routes queries back to the main
			// upstream immediately.
			BackoffDuration: 0,
		},
		FallbackAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort(fallback.LocalUDPAddr().String()),
			Timeout: testTimeout,
		}},
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

func TestHandler_Refresh_healthcheckNetworkOverride(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		upsNet   forward.Network
		override forward.Network
		want     forward.Network
	}{{
		name:     "any_no_override",
		upsNet:   forward.NetworkAny,
		override: "",
		want:     forward.NetworkUDP,
	}, {
		name:     "any_override_tcp",
		upsNet:   forward.NetworkAny,
		override: forward.NetworkTCP,
		want:     forward.NetworkTCP,
	}, {
		name:     "any_override_udp",
		upsNet:   forward.NetworkAny,
		override: forward.NetworkUDP,
		want:     forward.NetworkUDP,
	}, {
		name:     "udp_no_override",
		upsNet:   forward.NetworkUDP,
		override: "",
		want:     forward.NetworkUDP,
	}, {
		name:     "udp_override_tcp",
		upsNet:   forward.NetworkUDP,
		override: forward.NetworkTCP,
		want:     forward.NetworkTCP,
	}, {
		name:     "tcp_no_override",
		upsNet:   forward.NetworkTCP,
		override: "",
		want:     forward.NetworkTCP,
	}, {
		name:     "tcp_override_udp",
		upsNet:   forward.NetworkTCP,
		override: forward.NetworkUDP,
		want:     forward.NetworkUDP,
	}}

	fallbackAddrs := []*forward.UpstreamPlainConfig{{
		Network: forward.NetworkAny,
		Address: netip.MustParseAddrPort("192.0.2.1:53"),
		Timeout: testTimeout,
	}}

	for _, tc := range testCases {
		hcConf := &forward.HealthcheckConfig{
			Enabled:         true,
			DomainTempalate: "${RANDOM}.upstream-check.example",
			NetworkOverride: tc.override,
			InitDuration:    testTimeout,
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hf := func(ctx context.Context, w dnsserver.ResponseWriter, m *dns.Msg) (err error) {
				actualNet, err := forward.NewNetwork(w.RemoteAddr().Network())
				// Race shouldn't happen as the initial refresh is performed in
				// the main goroutine.
				require.NoError(t, err)
				require.Equal(t, tc.want, actualNet)

				return w.WriteMsg(ctx, m, (&dns.Msg{}).SetReply(m))
			}

			// Start the server inside the subtest as it adds a cleanup.
			upstreamSrv, _ := dnsservertest.RunDNSServer(t, dnsserver.HandlerFunc(hf))
			upstreamAddrs := []*forward.UpstreamPlainConfig{{
				Network: tc.upsNet,
				Address: netutil.NetAddrToAddrPort(upstreamSrv.LocalUDPAddr()),
				Timeout: testTimeout,
			}}

			handler := forward.NewHandler(&forward.HandlerConfig{
				Logger:             slogutil.NewDiscardLogger(),
				UpstreamsAddresses: upstreamAddrs,
				FallbackAddresses:  fallbackAddrs,
				Healthcheck:        hcConf,
			})
			testutil.CleanupAndRequireSuccess(t, handler.Close)
		})
	}
}
