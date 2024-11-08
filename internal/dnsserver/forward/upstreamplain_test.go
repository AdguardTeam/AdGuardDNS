package forward_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamPlain_Exchange(t *testing.T) {
	testCases := []struct {
		name    string
		network forward.Network
		want    forward.Network
	}{{
		name:    "any",
		network: forward.NetworkAny,
		want:    forward.NetworkUDP,
	}, {
		name:    "udp",
		network: forward.NetworkUDP,
		want:    forward.NetworkUDP,
	}, {
		name:    "tcp",
		network: forward.NetworkTCP,
		want:    forward.NetworkTCP,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, addr := dnsservertest.RunDNSServer(t, dnsservertest.NewDefaultHandler())
			ups := forward.NewUpstreamPlain(&forward.UpstreamPlainConfig{
				Network: tc.network,
				Address: netip.MustParseAddrPort(addr),
			})
			testutil.CleanupAndRequireSuccess(t, ups.Close)

			req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
			res, nw, err := ups.Exchange(testutil.ContextWithTimeout(t, testTimeout), req)
			require.NoError(t, err)
			require.NotNil(t, res)
			dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)

			assert.Equal(t, tc.want, nw)
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
		handler := dnsservertest.NewDefaultHandler()
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

	_, addrStr := dnsservertest.RunDNSServer(t, handlerFunc)

	// Create a test message.
	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)

	// First, check that we receive truncated response over UDP.
	addr := netip.MustParseAddrPort(addrStr)
	uUDP := forward.NewUpstreamPlain(&forward.UpstreamPlainConfig{
		Network: forward.NetworkUDP,
		Address: addr,
	})
	defer log.OnCloserError(uUDP, log.DEBUG)

	res, nw, err := uUDP.Exchange(testutil.ContextWithTimeout(t, testTimeout), req)
	require.NoError(t, err)
	dnsservertest.RequireResponse(t, req, res, 0, dns.RcodeSuccess, true)

	assert.Equal(t, forward.NetworkUDP, nw)

	// Second, check that nothing is truncated over TCP.
	uTCP := forward.NewUpstreamPlain(&forward.UpstreamPlainConfig{
		Network: forward.NetworkTCP,
		Address: addr,
	})
	defer log.OnCloserError(uTCP, log.DEBUG)

	res, nw, err = uTCP.Exchange(testutil.ContextWithTimeout(t, testTimeout), req)
	require.NoError(t, err)
	dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)

	assert.Equal(t, forward.NetworkTCP, nw)

	// Now with NetworkANY response is also not truncated since the upstream
	// fallbacks to TCP.
	uAny := forward.NewUpstreamPlain(&forward.UpstreamPlainConfig{
		Network: forward.NetworkAny,
		Address: addr,
	})
	defer log.OnCloserError(uAny, log.DEBUG)

	res, nw, err = uAny.Exchange(testutil.ContextWithTimeout(t, testTimeout), req)
	require.NoError(t, err)
	dnsservertest.RequireResponse(t, req, res, 1, dns.RcodeSuccess, false)

	assert.Equal(t, forward.NetworkTCP, nw)
}

func TestUpstreamPlain_Exchange_fallbackFail(t *testing.T) {
	pt := testutil.PanicT{}

	// Use only unbuffered channels to block until received and validated.
	netCh := make(chan string)
	respCh := make(chan struct{})

	h := dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		req *dns.Msg,
	) (err error) {
		testutil.RequireSend(pt, netCh, rw.RemoteAddr().Network(), testTimeout)

		resp := dnsservertest.NewResp(dns.RcodeSuccess, req)

		// Make all responses invalid.
		resp.Id = req.Id + 1

		return rw.WriteMsg(ctx, req, resp)
	})

	_, addr := dnsservertest.RunDNSServer(t, h)
	u := forward.NewUpstreamPlain(&forward.UpstreamPlainConfig{
		Network: forward.NetworkUDP,
		Address: netip.MustParseAddrPort(addr),
	})
	testutil.CleanupAndRequireSuccess(t, u.Close)

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)

	var resp *dns.Msg
	var err error
	go func() {
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		resp, _, err = u.Exchange(ctx, req)
		testutil.RequireSend(pt, respCh, struct{}{}, testTimeout)
	}()

	// First attempt should use UDP and fail due to bad ID.
	network, _ := testutil.RequireReceive(t, netCh, testTimeout)
	require.Equal(t, string(forward.NetworkUDP), network)

	// Second attempt should use TCP and succeed.
	network, _ = testutil.RequireReceive(t, netCh, testTimeout)
	require.Equal(t, string(forward.NetworkTCP), network)

	testutil.RequireReceive(t, respCh, testTimeout)
	require.ErrorIs(t, err, dns.ErrId)
	assert.NotNil(t, resp)
}

func TestUpstreamPlain_Exchange_fallbackSuccess(t *testing.T) {
	const (
		// network is set to UDP to ensure that falling back to TCP will still
		// be performed.
		network = forward.NetworkUDP

		goodDomain = "domain.example."
		badDomain  = "bad.example."
	)

	pt := testutil.PanicT{}

	req := dnsservertest.CreateMessage(goodDomain, dns.TypeA)
	resp := dnsservertest.NewResp(dns.RcodeSuccess, req)

	// Prepare malformed responses.

	badIDResp := resp.Copy()
	badIDResp.Id = ^req.Id

	badQNumResp := resp.Copy()
	badQNumResp.Question = append(badQNumResp.Question, req.Question[0])

	badQnameResp := resp.Copy()
	badQnameResp.Question[0].Name = badDomain

	badQtypeResp := resp.Copy()
	badQtypeResp.Question[0].Qtype = dns.TypeMX

	testCases := []struct {
		udpResp *dns.Msg
		name    string
	}{{
		udpResp: badIDResp,
		name:    "wrong_id",
	}, {
		udpResp: badQNumResp,
		name:    "wrong_question_number",
	}, {
		udpResp: badQnameResp,
		name:    "wrong_qname",
	}, {
		udpResp: badQtypeResp,
		name:    "wrong_qtype",
	}}

	for _, tc := range testCases {
		clonedReq := req.Copy()
		badResp := tc.udpResp.Copy()
		goodResp := resp.Copy()

		// Use only unbuffered channels to block until received and validated.
		netCh := make(chan string)
		respCh := make(chan struct{})

		h := dnsserver.HandlerFunc(func(
			ctx context.Context,
			rw dnsserver.ResponseWriter,
			req *dns.Msg,
		) (err error) {
			network := rw.RemoteAddr().Network()
			testutil.RequireSend(pt, netCh, network, testTimeout)

			if network == string(forward.NetworkUDP) {
				// Respond with invalid message via UDP.
				return rw.WriteMsg(ctx, req, badResp)
			}

			// Respond with valid message via TCP.
			return rw.WriteMsg(ctx, req, goodResp)
		})

		t.Run(tc.name, func(t *testing.T) {
			_, addr := dnsservertest.RunDNSServer(t, dnsserver.HandlerFunc(h))

			u := forward.NewUpstreamPlain(&forward.UpstreamPlainConfig{
				Network: network,
				Address: netip.MustParseAddrPort(addr),
			})
			testutil.CleanupAndRequireSuccess(t, u.Close)

			var actualResp *dns.Msg
			var err error
			go func() {
				ctx := testutil.ContextWithTimeout(t, testTimeout)
				actualResp, _, err = u.Exchange(ctx, clonedReq)
				testutil.RequireSend(pt, respCh, struct{}{}, testTimeout)
			}()

			// First attempt should use UDP and fail due to bad ID.
			network, _ := testutil.RequireReceive(t, netCh, testTimeout)
			require.Equal(t, string(forward.NetworkUDP), network)

			// Second attempt should use TCP and succeed.
			network, _ = testutil.RequireReceive(t, netCh, testTimeout)
			require.Equal(t, string(forward.NetworkTCP), network)

			testutil.RequireReceive(t, respCh, testTimeout)
			require.NoError(t, err)
			dnsservertest.RequireResponse(t, req, actualResp, 0, dns.RcodeSuccess, false)
		})
	}
}
