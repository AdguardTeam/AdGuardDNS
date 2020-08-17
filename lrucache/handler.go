package lrucache

import (
	"fmt"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// ServeDNS handles the DNS request and refuses if it's an ANY request
func (p *plug) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) != 1 {
		// google DNS, bind and others do the same
		return dns.RcodeFormatError, fmt.Errorf("got DNS request with != 1 questions")
	}

	reply, ok := p.cache.Get(r)
	if ok {
		lruCacheHits.Inc()

		_ = w.WriteMsg(reply)
		return reply.Rcode, nil
	}

	lruCacheMisses.Inc()

	cw := &CacheWriter{
		ResponseWriter: w,
		cache:          p.cache,
	}
	return plugin.NextOrFailure(p.Name(), p.Next, ctx, cw, r)
}
