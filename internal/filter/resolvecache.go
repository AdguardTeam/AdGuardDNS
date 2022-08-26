package filter

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Resolve Cache

// resolveCache caches resolved results for hosts for 24 hours.  Use it when you
// need to cache results of lookups of hostnames that don't change IP addresses
// that often.
type resolveCache struct {
	resolver agd.Resolver

	// mu protects ip4 and ip6.
	mu  *sync.RWMutex
	ip4 map[string]*resolveCacheItem
	ip6 map[string]*resolveCacheItem
}

// resolveCacheItem is an item of the resolved IP cache.
type resolveCacheItem struct {
	refr time.Time
	ips  []net.IP
}

// newResolveCache returns a new resolved IP cache.
func newResolveCache(resolver agd.Resolver) (c *resolveCache) {
	return &resolveCache{
		resolver: resolver,

		mu:  &sync.RWMutex{},
		ip4: map[string]*resolveCacheItem{},
		ip6: map[string]*resolveCacheItem{},
	}
}

// resolve returns the cached IPs.  network must be either "ip4" or "ip6".
func (c *resolveCache) resolve(network, addr string) (ips []net.IP, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var item *resolveCacheItem
	if network == netIP4 {
		item = c.ip4[addr]
	} else {
		item = c.ip6[addr]
	}

	// TODO(ameshkov): Consider making configurable.
	if item == nil || time.Since(item.refr) > 1*timeutil.Day {
		item, err = c.refresh(network, addr)
		if err != nil {
			return nil, err
		}
	}

	return item.ips, nil
}

// refresh refreshes the IP addresses.
func (c *resolveCache) refresh(network, addr string) (item *resolveCacheItem, err error) {
	var ips []net.IP

	refr := time.Now()

	// Don't resolve IP addresses.
	ip := net.ParseIP(addr)
	if ip != nil {
		ip4 := ip.To4()
		if (network == netIP4 && ip4 != nil) || (network == netIP6 && ip4 == nil) {
			ips = []net.IP{ip}
		} else {
			// Not the right kind of IP address.  Cache absence of IP addresses
			// for this network forever.
			ips = []net.IP{}
		}

		// Set the refresh time to the maximum date that time.Duration allows to
		// prevent this item from refreshing.
		refr = time.Unix(0, math.MaxInt64)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()

		ips, err = c.resolver.LookupIP(ctx, network, addr)
		if err != nil {
			if !isExpectedLookupError(network, err) {
				return nil, fmt.Errorf("resolving %s addr for %q: %w", network, addr, err)
			}

			log.Debug("resolve cache: warning: %s", err)
		}
	}

	item = &resolveCacheItem{
		refr: refr,
		ips:  ips,
	}
	if network == netIP4 {
		c.ip4[addr] = item
	} else {
		c.ip6[addr] = item
	}

	return item, nil
}

// isExpectedLookupError returns true if the error is an expected lookup error.
func isExpectedLookupError(network string, err error) (ok bool) {
	var dnsErr *net.DNSError
	if network == netIP6 && errors.As(err, &dnsErr) {
		// It's expected that Go default DNS resolver returns a DNS error in
		// some cases when it receives an empty response.  It's unclear what
		// exactly triggers this error, though.
		//
		// TODO(ameshkov): Consider researching this in detail.
		return true
	}

	var addrErr *net.AddrError
	if !errors.As(err, &addrErr) {
		return false
	}

	// Expect the error about no suitable addresses.  For example, no IPv6
	// addresses for a host that does have IPv4 ones.
	//
	// See function filterAddrList in ${GOROOT}/src/net/ipsock.go.
	return addrErr.Err == "no suitable address found"
}
