package upstream

import (
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestProxyConnectionReuse(t *testing.T) {
	srv := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		_ = w.WriteMsg(ret)
	})
	defer srv.Close()

	p, _ := NewProxy(srv.Addr)
	defer p.Close()

	// Test reuse for a UDP connection
	for i := 0; i < 100; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.org.", dns.TypeA)

		ret, cached, err := p.exchangeProto("udp", req)
		assert.Nil(t, err)
		if i > 0 {
			assert.True(t, cached)
		}
		assert.NotNil(t, ret)
		assert.True(t, ret.Response)
	}

	// Test reuse for a TCP connection
	for i := 0; i < 100; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.org.", dns.TypeA)

		ret, cached, err := p.exchangeProto("tcp", req)
		assert.Nil(t, err)
		if i > 0 {
			assert.True(t, cached)
		}
		assert.NotNil(t, ret)
		assert.True(t, ret.Response)
	}
}

func TestTimeout(t *testing.T) {
	srv := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {})
	defer srv.Close()

	p, _ := NewProxy(srv.Addr)
	defer p.Close()

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	ret, err := p.Exchange(req)

	assert.Nil(t, ret)
	assert.NotNil(t, err)
	assert.True(t, isTimeout(err))
}

func TestHandleTruncatedResponse(t *testing.T) {
	srv := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		state := request.Request{W: w, Req: r}

		ret := new(dns.Msg)
		ret.SetReply(r)
		if state.Proto() == "udp" {
			ret.Truncated = true
		}
		_ = w.WriteMsg(ret)
	})
	defer srv.Close()

	p, _ := NewProxy(srv.Addr)
	defer p.Close()

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	ret, err := p.Exchange(req)
	assert.Nil(t, err)
	assert.NotNil(t, ret)
	assert.False(t, ret.Truncated)
}

func TestProxyIPv6(t *testing.T) {
	p, err := NewProxy("::")
	assert.Nil(t, err)
	assert.NotNil(t, p)
	assert.Equal(t, "[::]:53", p.addr)

	p, err = NewProxy("1.1.1.1")
	assert.Nil(t, err)
	assert.NotNil(t, p)
	assert.Equal(t, "1.1.1.1:53", p.addr)

	p, err = NewProxy("1.1.1.1:53")
	assert.Nil(t, err)
	assert.NotNil(t, p)
	assert.Equal(t, "1.1.1.1:53", p.addr)

	p, err = NewProxy("[::]:53")
	assert.Nil(t, err)
	assert.NotNil(t, p)
	assert.Equal(t, "[::]:53", p.addr)

	p, err = NewProxy("[::]")
	assert.NotNil(t, err)
	assert.Nil(t, p)

	p, err = NewProxy("[::]::::53")
	assert.NotNil(t, err)
	assert.Nil(t, p)
}
