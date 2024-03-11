package accessmw_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/accessmw"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

func TestMiddleware_Wrap(t *testing.T) {
	am, accessErr := access.NewGlobal([]string{
		"block.test",
		"UPPERCASE.test",
		"||block_aaaa.test^$dnstype=AAAA",
	}, []netip.Prefix{
		netip.MustParsePrefix("1.1.1.1/32"),
		netip.MustParsePrefix("2.2.2.0/8"),
	})
	require.NoError(t, accessErr)

	amw := accessmw.New(&accessmw.Config{
		AccessManager: am,
	})

	testCases := []struct {
		wantResp assert.BoolAssertionFunc
		name     string
		host     string
		ip       net.IP
		qtype    uint16
	}{{
		ip:       net.IP{1, 1, 1, 0},
		name:     "pass_ip",
		host:     "pass.test",
		qtype:    dns.TypeA,
		wantResp: assert.True,
	}, {
		name:     "block_ip",
		ip:       net.IP{1, 1, 1, 1},
		host:     "pass.test",
		qtype:    dns.TypeA,
		wantResp: assert.False,
	}, {
		name:     "pass_subnet",
		ip:       net.IP{1, 2, 2, 2},
		host:     "pass.test",
		qtype:    dns.TypeA,
		wantResp: assert.True,
	}, {
		name:     "block_subnet",
		ip:       net.IP{2, 2, 2, 2},
		host:     "pass.test",
		qtype:    dns.TypeA,
		wantResp: assert.False,
	}, {
		wantResp: assert.True,
		name:     "pass_domain",
		host:     "pass.test",
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.False,
		name:     "blocked_domain_A",
		host:     "block.test",
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.False,
		name:     "blocked_domain_HTTPS",
		host:     "block.test",
		qtype:    dns.TypeHTTPS,
	}, {
		wantResp: assert.False,
		name:     "uppercase_domain",
		host:     "uppercase.test",
		qtype:    dns.TypeHTTPS,
	}, {
		wantResp: assert.True,
		name:     "pass_qt",
		host:     "block_aaaa.test",
		qtype:    dns.TypeA,
	}, {
		wantResp: assert.False,
		name:     "block_qt",
		host:     "block_aaaa.test",
		qtype:    dns.TypeAAAA,
	}}

	var handler dnsserver.Handler = dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		q *dns.Msg,
	) (_ error) {
		resp := dnsservertest.NewResp(
			dns.RcodeSuccess,
			q,
			dnsservertest.SectionAnswer{
				dnsservertest.NewA("test.domain", 0, netip.MustParseAddr("5.5.5.5")),
			},
		)

		err := rw.WriteMsg(ctx, q, resp)
		if err != nil {
			return err
		}

		return nil
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(nil, &net.TCPAddr{IP: tc.ip, Port: 5357})
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   tc.host,
					Qtype:  tc.qtype,
					Qclass: dns.ClassINET,
				}},
			}

			h := amw.Wrap(handler)
			err := h.ServeDNS(context.Background(), rw, req)
			require.NoError(t, err)

			resp := rw.Msg()
			tc.wantResp(t, resp != nil)
		})
	}
}
