package ratelimitmw_test

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/ratelimitmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_Wrap_access(t *testing.T) {
	const (
		domainBlockedNormal    = "www." + dnssvctest.DomainBlocked
		domainBlockedUppercase = "UPPERCASE." + dnssvctest.DomainBlocked
		domainBlockedRule      = "rule." + dnssvctest.DomainBlocked

		ruleBlocked = `||` + domainBlockedRule + `^$dnstype=AAAA`
	)

	var (
		allowedClient1IP = netip.MustParseAddr("192.0.2.1")
		allowedClient2IP = netip.MustParseAddr("2001:db8:ffff::")
		blockedClient1IP = netip.MustParseAddr("192.0.2.2")
		blockedClient2IP = netip.MustParseAddr("2001:db8::1")

		blockedClient2Prefix = netip.MustParsePrefix("2001:db8::/120")
	)

	accessMgr, errAccess := access.NewGlobal(
		[]string{
			domainBlockedNormal,
			domainBlockedUppercase,
			ruleBlocked,
		},
		[]netip.Prefix{
			errors.Must(blockedClient1IP.Prefix(blockedClient1IP.BitLen())),
			blockedClient2Prefix,
		},
	)
	require.NoError(t, errAccess)

	geoIP := agdtest.NewGeoIP()
	geoIP.OnData = func(_ string, _ netip.Addr) (l *geoip.Location, err error) {
		return nil, nil
	}

	rlMw := ratelimitmw.New(&ratelimitmw.Config{
		Logger:         slogutil.NewDiscardLogger(),
		Messages:       agdtest.NewConstructor(t),
		FilteringGroup: &agd.FilteringGroup{},
		ServerGroup:    &agd.ServerGroup{},
		Server: &agd.Server{
			// Use a DoT server to prevent ratelimiting.
			Protocol: agd.ProtoDoT,
		},
		StructuredErrors: agdtest.NewSDEConfig(true),
		AccessManager:    accessMgr,
		DeviceFinder: &agdtest.DeviceFinder{
			OnFind: func(_ context.Context, _ *dns.Msg, _, _ netip.AddrPort) (r agd.DeviceResult) {
				return nil
			},
		},
		ErrColl: agdtest.NewErrorCollector(),
		GeoIP:   geoIP,
		Metrics: ratelimitmw.EmptyMetrics{},
		Limiter: agdtest.NewRateLimit(),
		Protocols: []agd.Protocol{
			agd.ProtoDNS,
		},
		EDEEnabled: true,
	})

	testCases := []struct {
		wantResp assert.BoolAssertionFunc
		remoteIP netip.Addr
		name     string
		host     string
		qtype    dnsmsg.RRType
	}{{
		wantResp: assert.True,
		remoteIP: allowedClient1IP,
		name:     "pass_ip",
		host:     dnssvctest.DomainAllowed,
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.False,
		remoteIP: blockedClient1IP,
		name:     "block_ip",
		host:     dnssvctest.DomainAllowed,
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.True,
		remoteIP: allowedClient2IP,
		name:     "pass_subnet",
		host:     dnssvctest.DomainAllowed,
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.False,
		remoteIP: blockedClient2IP,
		name:     "block_subnet",
		host:     dnssvctest.DomainAllowed,
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.True,
		remoteIP: allowedClient1IP,
		name:     "pass_domain",
		host:     dnssvctest.DomainAllowed,
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.False,
		remoteIP: allowedClient1IP,
		name:     "blocked_domain_A",
		host:     domainBlockedNormal,
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.False,
		remoteIP: allowedClient1IP,
		name:     "blocked_domain_HTTPS",
		host:     domainBlockedNormal,
		qtype:    dns.TypeHTTPS,
	}, {
		wantResp: assert.False,
		remoteIP: allowedClient1IP,
		name:     "uppercase_domain",
		host:     strings.ToLower(domainBlockedUppercase),
		qtype:    dns.TypeHTTPS,
	}, {
		wantResp: assert.True,
		remoteIP: allowedClient1IP,
		name:     "pass_qt",
		host:     domainBlockedRule,
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.False,
		remoteIP: allowedClient1IP,
		name:     "block_qt",
		host:     domainBlockedRule,
		qtype:    dns.TypeAAAA,
	}}

	handler := dnsserver.HandlerFunc(func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (_ error) {
		return rw.WriteMsg(ctx, req, dnsservertest.NewResp(dns.RcodeSuccess, req))
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(nil, &net.TCPAddr{
				IP:   tc.remoteIP.AsSlice(),
				Port: 5357,
			})
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   tc.host,
					Qtype:  tc.qtype,
					Qclass: dns.ClassINET,
				}},
			}

			h := rlMw.Wrap(handler)
			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			err := h.ServeDNS(ctx, rw, req)
			require.NoError(t, err)

			resp := rw.Msg()
			tc.wantResp(t, resp != nil)
		})
	}
}
