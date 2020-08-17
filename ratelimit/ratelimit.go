package ratelimit

import (
	"sort"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/util"

	"go.uber.org/atomic"

	// ratelimiting and per-ip buckets
	"github.com/beefsack/go-rate"
	"github.com/patrickmn/go-cache"

	// coredns plugin
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

const defaultRatelimit = 30
const defaultBackOffLimit = 1000
const defaultResponseSize = 1000
const rateLimitersCacheTTL = time.Minute * 10
const backOffTTL = time.Minute * 30

var (
	rateLimitersCache = cache.New(rateLimitersCacheTTL, rateLimitersCacheTTL)
	backOffCache      = cache.New(backOffTTL, backOffTTL)
)

// ServeDNS handles the DNS request and refuses if it's an beyind specified ratelimit
func (p *plug) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	server := util.GetServer(ctx)

	if state.Proto() != "udp" {
		// Do not apply ratelimit plugin to non-UDP requests
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	ip := state.IP()
	if p.isBackOff(ip) {
		RateLimitedCounter.WithLabelValues(server).Inc()
		BackOffCounter.WithLabelValues(server).Inc()
		return 0, nil
	}

	allow, whitelisted, err := p.allowRequest(ip)
	if err != nil {
		return 0, err
	}
	if whitelisted {
		WhitelistedCounter.WithLabelValues(server).Inc()
	}
	if !allow {
		RateLimitedCounter.WithLabelValues(server).Inc()
		return 0, nil
	}

	// Record response to get status code and size of the reply.
	rw := dnstest.NewRecorder(w)
	status, err := plugin.NextOrFailure(p.Name(), p.Next, ctx, rw, r)

	size := rw.Len

	if size > defaultResponseSize && state.Proto() == "udp" {
		// For large UDP responses we call allowRequest more times
		// The exact number of times depends on the response size
		for i := 0; i < size/defaultResponseSize; i++ {
			_, _, _ = p.allowRequest(ip)
		}
	}

	return status, err
}

// allowRequest checks if this IP address is rate-limited or not
// returns allow, whitelisted, error
func (p *plug) allowRequest(ip string) (bool, bool, error) {
	if p.isWhitelisted(ip) {
		return true, true, nil
	}

	var rateLimiter *rate.RateLimiter

	rl, found := rateLimitersCache.Get(ip)
	if found {
		rateLimiter = rl.(*rate.RateLimiter)
	} else {
		rateLimiter = rate.New(p.ratelimit, time.Second)
		rateLimitersCache.Set(ip, rateLimiter, rateLimitersCacheTTL)
		RateLimitersCountGauge.Set(float64(rateLimitersCache.ItemCount()))
	}

	allow, _ := rateLimiter.Try()
	if !allow {
		p.countRateLimited(ip)
	}

	return allow, false, nil
}

// countRateLimited is called for the IP address which already got rate-limited
// if this continues to happen, and the IP address gets rate-limited more than X
// times during the backOffTTL period, the IP gets blocked until the backOffTTL
// period ends.
func (p *plug) countRateLimited(ip string) {
	var counter *atomic.Int64

	c, found := backOffCache.Get(ip)
	if !found {
		counter = atomic.NewInt64(0)
		backOffCache.Set(ip, counter, backOffTTL)
		RateLimitedIPAddressesCountGauge.Set(float64(backOffCache.ItemCount()))
	} else {
		counter = c.(*atomic.Int64)
	}

	counter.Inc()
}

// isBackOff checks if it is the backoff period for the specified IP
func (p *plug) isBackOff(ip string) bool {
	// backOffCache.
	c, found := backOffCache.Get(ip)
	if !found {
		return false
	}

	counter := c.(*atomic.Int64)
	return counter.Load() > int64(p.backOffLimit)
}

// isWhitelisted checks if the specified IP is whitelisted
func (p *plug) isWhitelisted(ip string) bool {
	if len(p.whitelist) > 0 {
		i := sort.SearchStrings(p.whitelist, ip)

		if i < len(p.whitelist) && p.whitelist[i] == ip {
			return true
		}
	}

	if p.consulURL == "" {
		return false
	}

	p.consulWhitelistGuard.Lock()
	if len(p.consulWhitelist) > 0 {
		i := sort.SearchStrings(p.consulWhitelist, ip)

		if i < len(p.consulWhitelist) && p.consulWhitelist[i] == ip {
			p.consulWhitelistGuard.Unlock()
			return true
		}
	}
	p.consulWhitelistGuard.Unlock()

	return false
}
