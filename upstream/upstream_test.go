package upstream

import (
	"context"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/test"

	"github.com/stretchr/testify/assert"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/miekg/dns"
)

func TestUpstreamSimpleResolve(t *testing.T) {
	srv := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		_ = w.WriteMsg(ret)
	})
	defer srv.Close()

	p, err := NewProxy(srv.Addr)
	assert.Nil(t, err)
	u := &Upstream{main: p}

	// Test reuse for a UDP connection
	for i := 0; i < 100; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.org.", dns.TypeA)

		rw := &test.ResponseWriter{}
		rrw := dnstest.NewRecorder(rw)

		rcode, err := u.ServeDNS(context.Background(), rrw, req)
		assert.Nil(t, err)
		assert.Equal(t, 0, rcode)
		assert.NotNil(t, rrw.Msg)
		assert.True(t, rrw.Msg.Response)
	}
}

func TestUpstreamFallback(t *testing.T) {
	srvAlive := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		_ = w.WriteMsg(ret)
	})

	// Listener that does nothing - we need it to emulate a dead upstream
	l, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	assert.Nil(t, err)
	defer l.Close()
	defer srvAlive.Close()

	p, err := NewProxy(l.LocalAddr().String())
	assert.Nil(t, err)
	u := &Upstream{main: p}

	p, err = NewProxy(srvAlive.Addr)
	assert.Nil(t, err)
	u.fallbacks = append(u.fallbacks, p)

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	rw := &test.ResponseWriter{}
	rrw := dnstest.NewRecorder(rw)

	// Check that query is answered even though the upstream is dead
	rcode, err := u.ServeDNS(context.Background(), rrw, req)
	assert.Nil(t, err)
	assert.Equal(t, 0, rcode)
	assert.NotNil(t, rrw.Msg)
	assert.True(t, rrw.Msg.Response)
}

func TestUpstreamFallbackServfail(t *testing.T) {
	srvAlive := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		_ = w.WriteMsg(ret)
	})
	defer srvAlive.Close()

	srvDead := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		ret.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(ret)
	})
	defer srvDead.Close()

	p, err := NewProxy(srvDead.Addr)
	assert.Nil(t, err)
	u := &Upstream{main: p}

	p, err = NewProxy(srvAlive.Addr)
	assert.Nil(t, err)
	u.fallbacks = append(u.fallbacks, p)

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	rw := &test.ResponseWriter{}
	rrw := dnstest.NewRecorder(rw)

	// Check that query is replied even though the upstream returns servfail
	rcode, err := u.ServeDNS(context.Background(), rrw, req)
	assert.Nil(t, err)
	assert.Equal(t, 0, rcode)
	assert.NotNil(t, rrw.Msg)
	assert.True(t, rrw.Msg.Response)
}
