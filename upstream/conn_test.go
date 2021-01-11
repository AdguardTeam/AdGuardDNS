package upstream

import (
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestConnUDP(t *testing.T) {
	srv := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		ret.Rcode = dns.RcodeSuccess

		state := request.Request{W: w, Req: r}
		if state.Proto() != "udp" {
			ret.Rcode = dns.RcodeServerFailure
		}

		_ = w.WriteMsg(ret)
	})
	defer srv.Close()

	conn := &Conn{
		addr:  srv.Addr,
		proto: "udp",
	}

	for i := 0; i < 100; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.org.", dns.TypeA)
		buf := make([]byte, 16*1024)

		ret, err := conn.Exchange(buf, req)
		assert.Nil(t, err)
		assert.NotNil(t, ret)
		assert.True(t, ret.Response)
		assert.Equal(t, dns.RcodeSuccess, ret.Rcode)
	}
}

func TestConnTCP(t *testing.T) {
	srv := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)

		state := request.Request{W: w, Req: r}
		if state.Proto() != "tcp" {
			ret.Rcode = dns.RcodeServerFailure
		}

		_ = w.WriteMsg(ret)
	})
	defer srv.Close()

	conn := &Conn{
		addr:  srv.Addr,
		proto: "tcp",
	}

	for i := 0; i < 100; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.org.", dns.TypeA)
		buf := make([]byte, 16*1024)

		ret, err := conn.Exchange(buf, req)
		assert.Nil(t, err)
		assert.NotNil(t, ret)
		assert.True(t, ret.Response)
		assert.Equal(t, dns.RcodeSuccess, ret.Rcode)
	}
}

func TestServFail(t *testing.T) {
	srv := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		ret.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(ret)
	})
	defer srv.Close()

	conn := &Conn{
		addr:  srv.Addr,
		proto: "udp",
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	buf := make([]byte, 16*1024)

	ret, err := conn.Exchange(buf, req)
	assert.Nil(t, err)
	assert.NotNil(t, ret)
	assert.Equal(t, dns.RcodeServerFailure, ret.Rcode)
}
