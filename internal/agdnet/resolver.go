package agdnet

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// Resolvers

// Resolver is the DNS resolver interface.
//
// See go doc net.Resolver.
type Resolver interface {
	LookupIP(ctx context.Context, fam netutil.AddrFamily, host string) (ips []net.IP, err error)
}

// DefaultResolver uses [net.DefaultResolver] to resolve addresses.
type DefaultResolver struct{}

// type check
var _ Resolver = DefaultResolver{}

// LookupIP implements the [Resolver] interface for DefaultResolver.
func (DefaultResolver) LookupIP(
	ctx context.Context,
	fam netutil.AddrFamily,
	host string,
) (ips []net.IP, err error) {
	switch fam {
	case netutil.AddrFamilyIPv4:
		return net.DefaultResolver.LookupIP(ctx, "ip4", host)
	case netutil.AddrFamilyIPv6:
		return net.DefaultResolver.LookupIP(ctx, "ip6", host)
	default:
		return nil, net.UnknownNetworkError(fam.String())
	}
}

// resolveCache is a simple address resolving cache.
type resolveCache map[string]*resolveCacheItem

// resolveCacheItem is an item of [resolveCache].
type resolveCacheItem struct {
	refrTime time.Time
	ips      []net.IP
}

// CachingResolver caches resolved results for hosts for a certain time,
// regardless of the actual TTLs of the records.  It is used for caching the
// results of lookups of hostnames that don't change their IP addresses often.
type CachingResolver struct {
	resolver Resolver

	// mu protects ip4 and ip6.
	mu   *sync.Mutex
	ipv4 resolveCache
	ipv6 resolveCache

	ttl time.Duration
}

// NewCachingResolver returns a new caching resolver.
func NewCachingResolver(resolver Resolver, ttl time.Duration) (c *CachingResolver) {
	return &CachingResolver{
		resolver: resolver,

		mu:   &sync.Mutex{},
		ipv4: resolveCache{},
		ipv6: resolveCache{},

		ttl: ttl,
	}
}

// type check
var _ Resolver = (*CachingResolver)(nil)

// LookupIP implements the [Resolver] interface for *CachingResolver.  host
// should be normalized.  Slice ips and its elements must not be mutated.
func (c *CachingResolver) LookupIP(
	ctx context.Context,
	fam netutil.AddrFamily,
	host string,
) (ips []net.IP, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var item *resolveCacheItem
	switch fam {
	case netutil.AddrFamilyIPv4:
		item = c.ipv4[host]
	case netutil.AddrFamilyIPv6:
		item = c.ipv6[host]
	default:
		return nil, net.UnknownNetworkError(fam.String())
	}

	if item == nil || time.Since(item.refrTime) > c.ttl {
		item, err = c.resolve(ctx, fam, host)
		if err != nil {
			return nil, err
		}
	}

	return item.ips, nil
}

// resolve looks up the IP addresses for host and puts them into the cache.
func (c *CachingResolver) resolve(
	ctx context.Context,
	fam netutil.AddrFamily,
	host string,
) (item *resolveCacheItem, err error) {
	var ips []net.IP

	refrTime := time.Now()

	// Don't resolve IP addresses.
	ip := net.ParseIP(host)
	if ip != nil {
		ip4 := ip.To4()
		if fam == netutil.AddrFamilyIPv4 && ip4 != nil {
			ips = []net.IP{ip4}
		} else if fam == netutil.AddrFamilyIPv6 && ip4 == nil {
			ips = []net.IP{ip}
		} else {
			// Not the right kind of IP address.  Cache absence of IP addresses
			// for this network forever.
			ips = []net.IP{}
		}

		// Set the refresh time to the maximum date that time.Duration allows to
		// prevent this item from refreshing.
		refrTime = time.Unix(0, math.MaxInt64)
	} else {
		ips, err = c.resolver.LookupIP(ctx, fam, host)
		if err != nil {
			if !isExpectedLookupError(fam, err) {
				return nil, fmt.Errorf("resolving %s addr for %q: %w", fam, host, err)
			}

			log.Debug("caching resolver: warning: %s", err)
		}
	}

	var cache resolveCache
	if fam == netutil.AddrFamilyIPv4 {
		cache = c.ipv4
	} else {
		cache = c.ipv6
	}

	item = &resolveCacheItem{
		refrTime: refrTime,
		ips:      ips,
	}

	cache[host] = item

	return item, nil
}

// isExpectedLookupError returns true if the error is an expected lookup error.
func isExpectedLookupError(fam netutil.AddrFamily, err error) (ok bool) {
	var dnsErr *net.DNSError
	if fam == netutil.AddrFamilyIPv6 && errors.As(err, &dnsErr) {
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
