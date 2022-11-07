package ratelimit_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

func TestRatelimitMiddleware(t *testing.T) {
	const rps = 10

	persistent := []netip.Prefix{
		netip.MustParsePrefix("4.3.2.1/8"),
	}
	clientAddr := &net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 1}
	clientAddrV6 := &net.UDPAddr{IP: net.ParseIP("2001:470:b083:310:d2a3:c9a5:3f3b:6f5a"), Port: 1}

	const testFQDN = "example.org."
	commonMsg := dnsservertest.CreateMessage(testFQDN, dns.TypeA)

	testCases := []struct {
		remoteAddr net.Addr
		req        *dns.Msg
		name       string
		respCount  int
		reqsNum    int
		wantResps  int
	}{{
		remoteAddr: clientAddr,
		req:        commonMsg,
		name:       "common",
		respCount:  1,
		reqsNum:    rps * 2,
		wantResps:  rps,
	}, {
		remoteAddr: clientAddrV6,
		req:        commonMsg,
		name:       "common_v6",
		respCount:  1,
		reqsNum:    rps * 2,
		wantResps:  rps,
	}, {
		remoteAddr: &net.UDPAddr{IP: net.IP{4, 3, 2, 1}, Port: 1},
		req:        commonMsg,
		name:       "allowlist",
		respCount:  1,
		reqsNum:    rps * 2,
		wantResps:  rps * 2,
	}, {
		remoteAddr: &net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 0},
		req:        commonMsg,
		name:       "spoofer",
		respCount:  1,
		reqsNum:    rps,
		wantResps:  0,
	}, {
		remoteAddr: clientAddr,
		req:        commonMsg,
		name:       "large_msg",
		respCount:  100,
		reqsNum:    2,
		wantResps:  1,
	}, {
		remoteAddr: clientAddr,
		req:        dnsservertest.CreateMessage(testFQDN, dns.TypeANY),
		name:       "any",
		respCount:  1,
		reqsNum:    rps,
		wantResps:  0,
	}, {
		remoteAddr: clientAddr,
		req:        commonMsg,
		name:       "hit_backoff",
		respCount:  1,
		reqsNum:    rps * 100,
		wantResps:  rps,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rl := ratelimit.NewBackOff(&ratelimit.BackOffConfig{
				Allowlist:            ratelimit.NewDynamicAllowlist(persistent, nil),
				Period:               time.Minute,
				Duration:             time.Minute,
				Count:                rps,
				ResponseSizeEstimate: 128,
				RPS:                  rps,
				IPv4SubnetKeyLen:     24,
				IPv6SubnetKeyLen:     48,
				RefuseANY:            true,
			})
			rlMw, err := ratelimit.NewMiddleware(rl, []dnsserver.Protocol{
				dnsserver.ProtoDNS,
			})
			require.NoError(t, err)

			withMw := dnsserver.WithMiddlewares(
				dnsservertest.CreateTestHandler(tc.respCount),
				rlMw,
			)

			ctx := dnsserver.ContextWithServerInfo(context.Background(), dnsserver.ServerInfo{
				Name:  "test",
				Addr:  "127.0.0.1",
				Proto: dnsserver.ProtoDNS,
			})
			ctx = dnsserver.ContextWithStartTime(ctx, time.Now())
			ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{})

			n := 0
			for i := 0; i < tc.reqsNum; i++ {
				nrw := dnsserver.NewNonWriterResponseWriter(
					&net.UDPAddr{IP: []byte{1, 2, 3, 4}},
					tc.remoteAddr,
				)
				err = withMw.ServeDNS(ctx, nrw, tc.req)
				require.NoError(t, err)

				if nrw.Msg() != nil {
					n++
				}
			}

			assert.Equal(t, tc.wantResps, n)
		})
	}
}
