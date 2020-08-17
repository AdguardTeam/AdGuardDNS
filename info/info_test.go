package info

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/stretchr/testify/assert"
)

func TestInfoCheckRequest(t *testing.T) {
	cfg := `info {
					domain adguard.com
					canary dnscheck.adguard.com
					protocol auto
					type test
					addr 176.103.130.132 176.103.130.134 2a00:5a60::bad1:ff 2a00:5a60::bad2:ff
				}`
	c := caddy.NewTestController("info", cfg)
	c.ServerBlockKeys = []string{""}
	i, err := setupPlugin(c)
	assert.Nil(t, err)

	// Prepare context
	srv := &dnsserver.Server{Addr: "https://"}
	ctx := context.WithValue(context.Background(), dnsserver.Key{}, srv)

	// Prepare response writer
	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)

	// --
	// Test type=A queries

	// Prepare test request
	req := new(dns.Msg)
	req.SetQuestion("32132124-doh-test-dnscheck.adguard.com", dns.TypeA)

	// Pass to the plugin
	rCode, err := i.ServeDNS(ctx, rrw, req)

	// Check rcode and error first
	assert.Nil(t, err)
	assert.Equal(t, dns.RcodeSuccess, rCode)

	// Now let's check the response
	assert.NotNil(t, rrw.Msg)
	assert.Equal(t, len(rrw.Msg.Answer), 2)

	a1, ok := rrw.Msg.Answer[0].(*dns.A)
	assert.True(t, ok)
	assert.Equal(t, "176.103.130.132", a1.A.String())

	a2, ok := rrw.Msg.Answer[1].(*dns.A)
	assert.True(t, ok)
	assert.Equal(t, "176.103.130.134", a2.A.String())

	// --
	// Test type=AAAA queries

	// Prepare test request
	req = new(dns.Msg)
	req.SetQuestion("32132124-doh-test-dnscheck.adguard.com", dns.TypeAAAA)

	// Pass to the plugin
	rCode, err = i.ServeDNS(ctx, rrw, req)

	// Check rcode and error first
	assert.Nil(t, err)
	assert.Equal(t, dns.RcodeSuccess, rCode)

	// Now let's check the response
	assert.NotNil(t, rrw.Msg)
	assert.Equal(t, len(rrw.Msg.Answer), 2)

	aaaa1, ok := rrw.Msg.Answer[0].(*dns.AAAA)
	assert.True(t, ok)
	assert.Equal(t, "2a00:5a60::bad1:ff", aaaa1.AAAA.String())

	aaaa2, ok := rrw.Msg.Answer[1].(*dns.AAAA)
	assert.True(t, ok)
	assert.Equal(t, "2a00:5a60::bad2:ff", aaaa2.AAAA.String())

	// --
	// Test canary domain

	// Prepare test request
	req = new(dns.Msg)
	req.SetQuestion("dnscheck.adguard.com", dns.TypeA)

	// Pass to the plugin
	rCode, err = i.ServeDNS(ctx, rrw, req)

	// Check rcode and error first
	assert.Nil(t, err)
	assert.Equal(t, dns.RcodeSuccess, rCode)

	// Now let's check the response
	assert.NotNil(t, rrw.Msg)
	assert.Equal(t, len(rrw.Msg.Answer), 2)

	a1, ok = rrw.Msg.Answer[0].(*dns.A)
	assert.True(t, ok)
	assert.Equal(t, "176.103.130.132", a1.A.String())

	a2, ok = rrw.Msg.Answer[1].(*dns.A)
	assert.True(t, ok)
	assert.Equal(t, "176.103.130.134", a2.A.String())
}
