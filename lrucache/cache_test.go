package lrucache

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestCache(t *testing.T) {
	cache := &cache{}

	// request with do
	req := new(dns.Msg)
	req.SetQuestion("testhost.", dns.TypeA)
	req.SetEdns0(4096, true)

	res := new(dns.Msg)
	res.SetReply(req)
	res.SetEdns0(4096, true)
	res.RecursionAvailable = true
	res.Answer = []dns.RR{
		test.A("testhost. 255 IN A 37.220.26.135"),
	}

	// save to cache
	cache.Set(res)

	// get from cache
	cachedRes, ok := cache.Get(req)
	assert.True(t, ok)
	assert.NotNil(t, cachedRes)
	assert.Equal(t, req.Question[0].Name, cachedRes.Question[0].Name)
}
