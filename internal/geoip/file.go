package geoip

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/oschwald/maxminddb-golang"
)

// Constants that define cache identifiers for the cache manager.
const (
	cachePrefix = "geoip/"

	cacheIDIP   = cachePrefix + "ip"
	cacheIDHost = cachePrefix + "host"
)

// FileConfig is the file-based GeoIP configuration structure.
type FileConfig struct {
	// Logger is used for logging the operation of the file-based GeoIP
	// database.
	Logger *slog.Logger

	// CacheManager is the global cache manager.  CacheManager must not be nil.
	CacheManager agdcache.Manager

	// AllTopASNs contains all subnets from CountryTopASNs.  While scanning the
	// statistics data file this set is used to check if the current ASN
	// included in CountryTopASNs.
	AllTopASNs *container.MapSet[ASN]

	// CountryTopASNs is a mapping of a country to their top ASNs.
	CountryTopASNs map[Country]ASN

	// ASNPath is the path to the GeoIP database of ASNs.
	ASNPath string

	// CountryPath is the path to the GeoIP database of countries.  The
	// databases containing subdivisions and cities info are also supported.
	CountryPath string

	// HostCacheCount is how many lookups are cached by hostname.  Zero means no
	// host caching is performed.
	HostCacheCount int

	// IPCacheCount is how many lookups are cached by IP address.
	IPCacheCount int
}

// File is a file implementation of [geoip.Interface].  It should be initially
// refreshed before use.
type File struct {
	logger *slog.Logger

	allTopASNs     *container.MapSet[ASN]
	countryTopASNs map[Country]ASN

	// mu protects asn, country, country subnet maps, and caches against
	// simultaneous access during a refresh.
	mu *sync.RWMutex

	asn     *maxminddb.Reader
	country *maxminddb.Reader

	// TODO(a.garipov): Consider switching fully to the country ASN method and
	// removing these.
	//
	// See AGDNS-710.
	// TODO(a.garipov): Switch to locationSubnets instead?
	ipv4CountrySubnets countrySubnets
	ipv6CountrySubnets countrySubnets

	ipv4LocationSubnets locationSubnets
	ipv6LocationSubnets locationSubnets

	ipCache   agdcache.Interface[any, *Location]
	hostCache agdcache.Interface[string, *Location]

	asnPath     string
	countryPath string
}

// countrySubnets is a country-to-subnet mapping.
type countrySubnets map[Country]netip.Prefix

// locationSubnets is a locationKey-to-subnet mapping.
type locationSubnets map[locationKey]netip.Prefix

// locationKey represents a key for locationSubnets mapping.
type locationKey struct {
	country        Country
	topSubdivision string
	asn            ASN
}

// newLocationKey returns a key for locationKey-to-subnet mapping.  The location
// with determined subdivision is used only for certain countries with the
// purpose to limit the total amount of items in the mapping.
//
// See AGDNS-1622.
func newLocationKey(asn ASN, ctry Country, subdiv string) (l locationKey) {
	switch ctry {
	case CountryRU, CountryUS, CountryCN, CountryIN:
		return locationKey{
			asn:            asn,
			country:        ctry,
			topSubdivision: subdiv,
		}
	default:
		return locationKey{
			asn: asn,
		}
	}
}

// NewFile returns a new GeoIP database that reads information from a file.  It
// also adds the caches with IDs [CacheIDIP] and [CacheIDHost] to the cache
// manager.
func NewFile(c *FileConfig) (f *File) {
	var hostCache agdcache.Interface[string, *Location]
	if c.HostCacheCount == 0 {
		hostCache = agdcache.Empty[string, *Location]{}
	} else {
		hostCache = agdcache.NewLRU[string, *Location](&agdcache.LRUConfig{
			Count: c.HostCacheCount,
		})
	}

	ipCache := agdcache.NewLRU[any, *Location](&agdcache.LRUConfig{
		Count: c.IPCacheCount,
	})

	c.CacheManager.Add(cacheIDHost, hostCache)
	c.CacheManager.Add(cacheIDIP, ipCache)

	return &File{
		logger: c.Logger,

		mu: &sync.RWMutex{},

		ipCache:   ipCache,
		hostCache: hostCache,

		asnPath:     c.ASNPath,
		countryPath: c.CountryPath,

		allTopASNs:     c.AllTopASNs,
		countryTopASNs: c.CountryTopASNs,
	}
}

// ipToCacheKey returns the cache key for ip.  The cache key is a three-byte
// array (/24 network) for IPv4 addresses (including the IPv4-in-IPv6 ones) and
// a seven-byte (/56 network) for IPv6 ones, based on recommendations from
// RFC 6177.
//
// TODO(a.garipov): Consider merging with similar logic for other cache keys,
// such as the one in package ratelimit of module dnsserver.
func ipToCacheKey(ip netip.Addr) (k any) {
	if ip.Is4() {
		a := ip.As4()

		return [3]byte(a[:])
	}

	a := ip.As16()

	return [7]byte(a[:])
}

// type check
var _ Interface = (*File)(nil)

// SubnetByLocation implements the Interface interface for *File.  fam must be
// either [netutil.AddrFamilyIPv4] or [netutil.AddrFamilyIPv6].  l must not be
// nil.
//
// The process of the subnet selection is as follows:
//
//  1. A list of the most common ASNs, including the top ASN for each country,
//     is pre-generated from the statistics data.  See file asntops_generate.go
//     and its output, asntops.go.
//
//  2. During the server startup, File scans through the provided GeoIP database
//     files searching for the fitting subnets for ASNs and countries.  See
//     [resetCountrySubnets] and [File.resetLocationSubnets].
//
//  3. If asn is found within the list of the most used ASNs, its subnet is
//     returned.  If not, the top ASN for the provided country is chosen and its
//     subnet is returned.  If the information about the most used ASNs is not
//     available, the first subnet from the country that is broad enough (see
//     resetCountrySubnets) is chosen.
func (f *File) SubnetByLocation(l *Location, fam netutil.AddrFamily) (n netip.Prefix, err error) {
	var ctrySubnets countrySubnets
	var locSubnets locationSubnets

	f.mu.RLock()
	defer f.mu.RUnlock()

	switch fam {
	case netutil.AddrFamilyIPv4:
		ctrySubnets = f.ipv4CountrySubnets
		locSubnets = f.ipv4LocationSubnets
	case netutil.AddrFamilyIPv6:
		ctrySubnets = f.ipv6CountrySubnets
		locSubnets = f.ipv6LocationSubnets
	default:
		panic(fmt.Errorf("geoip: unsupported addr fam %s", fam))
	}

	locKey := newLocationKey(l.ASN, l.Country, l.TopSubdivision)

	var ok bool
	if n, ok = locSubnets[locKey]; ok {
		// First lookup in location map.
		return n, nil
	} else if l.ASN, ok = f.countryTopASNs[l.Country]; ok {
		// Technically, if there is an entry in countryTopASNs then that entry
		// also always exists in topASNSubnets, but let's be defensive about it.
		if n, ok = locSubnets[newLocationKey(l.ASN, CountryNone, "")]; ok {
			return n, nil
		}
	}

	if n, ok = ctrySubnets[l.Country]; ok {
		return n, nil
	}

	return netutil.ZeroPrefix(fam), nil
}

// Data implements the Interface interface for *File.  If ip is netip.Addr{},
// Data tries to lookup and return the data based on host, unless it's empty.
func (f *File) Data(host string, ip netip.Addr) (l *Location, err error) {
	if ip == (netip.Addr{}) {
		return f.dataByHost(host), nil
	} else if ip.Is4In6() {
		// This can really only happen when querying data for ECS addresses,
		// since the remote IP address is normalized in dnssvc.ipFromNetAddr.
		// Normalize here, since we use SkipAliasedNetworks in file scanning.
		ip = netip.AddrFrom4(ip.As4())
	}

	cacheKey := ipToCacheKey(ip)
	item, ok := f.ipCache.Get(cacheKey)
	if ok {
		metrics.GeoIPCacheLookupsHits.Inc()

		return item, nil
	}

	metrics.GeoIPCacheLookupsMisses.Inc()

	f.mu.RLock()
	defer f.mu.RUnlock()

	asn, err := f.lookupASN(ip)
	if err != nil {
		return nil, fmt.Errorf("looking up asn: %w", err)
	}

	l = &Location{
		ASN: asn,
	}

	err = f.setCtry(l, ip)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	f.setCaches(host, cacheKey, l)

	return l, nil
}

// dataByHost returns GeoIP data that has been cached previously.
func (f *File) dataByHost(host string) (l *Location) {
	item, ok := f.hostCache.Get(host)

	metrics.IncrementCond(
		ok,
		metrics.GeoIPHostCacheLookupsHits,
		metrics.GeoIPHostCacheLookupsMisses,
	)

	return item
}

// asnResult is used to retrieve autonomous system number data from a GeoIP
// reader.
type asnResult struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
}

// lookupASN looks up and returns the autonomous system number part of the GeoIP
// data for ip.
func (f *File) lookupASN(ip netip.Addr) (asn ASN, err error) {
	// TODO(a.garipov): Remove AsSlice if oschwald/maxminddb-golang#88 is done.
	var res asnResult
	err = f.asn.Lookup(ip.AsSlice(), &res)
	if err != nil {
		return 0, fmt.Errorf("looking up asn: %w", err)
	}

	return ASN(res.ASN), nil
}

// countryResult is used to retrieve the continent and country data from a GeoIP
// reader.
type countryResult struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"subdivisions"`
}

// setCtry looks up and sets the country, continent and the subdivision parts
// of the GeoIP data for ip into loc.  loc must not be nil.
func (f *File) setCtry(loc *Location, ip netip.Addr) (err error) {
	// TODO(a.garipov): Remove AsSlice if oschwald/maxminddb-golang#88 is done.
	var res countryResult
	err = f.country.Lookup(ip.AsSlice(), &res)
	if err != nil {
		return fmt.Errorf("looking up country: %w", err)
	}

	loc.Country, err = NewCountry(res.Country.ISOCode)
	if err != nil {
		return fmt.Errorf("converting country: %w", err)
	}

	loc.Continent, err = NewContinent(res.Continent.Code)
	if err != nil {
		return fmt.Errorf("converting continent: %w", err)
	}

	if len(res.Subdivisions) > 0 {
		loc.TopSubdivision = res.Subdivisions[0].ISOCode
	}

	return nil
}

// setCaches sets the GeoIP data into the caches.
func (f *File) setCaches(host string, ipCacheKey any, l *Location) {
	f.ipCache.Set(ipCacheKey, l)

	if host == "" {
		return
	}

	f.hostCache.Set(host, l)
}

// Refresh implements the [agdservice.Refresher] interface for *File.  It
// reopens the GeoIP database files.
func (f *File) Refresh(ctx context.Context) (err error) {
	f.logger.InfoContext(ctx, "refresh started")
	defer f.logger.InfoContext(ctx, "refresh finished")

	asn, err := geoIPFromFile(f.asnPath)
	if err != nil {
		metrics.GeoIPUpdateStatus.WithLabelValues(f.asnPath).Set(0)

		return fmt.Errorf("reading asn geoip: %w", err)
	}

	country, err := geoIPFromFile(f.countryPath)
	if err != nil {
		metrics.GeoIPUpdateStatus.WithLabelValues(f.countryPath).Set(0)

		return fmt.Errorf("reading country geoip: %w", err)
	}

	err = f.resetSubnetMappings(ctx, asn, country)
	if err != nil {
		return fmt.Errorf("resetting geoip: %w", err)
	}

	metrics.GeoIPUpdateTime.WithLabelValues(f.asnPath).SetToCurrentTime()
	metrics.GeoIPUpdateStatus.WithLabelValues(f.asnPath).Set(1)
	metrics.GeoIPUpdateTime.WithLabelValues(f.countryPath).SetToCurrentTime()
	metrics.GeoIPUpdateStatus.WithLabelValues(f.countryPath).Set(1)

	f.mu.Lock()
	defer f.mu.Unlock()

	f.asn, f.country = asn, country

	f.hostCache.Clear()
	f.ipCache.Clear()

	return nil
}

// resetSubnetMappings refreshes mapping from GeoIP data.
func (f *File) resetSubnetMappings(
	ctx context.Context,
	asn *maxminddb.Reader,
	country *maxminddb.Reader,
) (err error) {
	var wg sync.WaitGroup
	wg.Add(2)

	var locErr, ctryErr error

	go func() {
		defer wg.Done()

		var ipv4, ipv6 locationSubnets
		ipv4, ipv6, locErr = f.resetLocationSubnets(ctx, asn, country)

		if locErr != nil {
			metrics.GeoIPUpdateStatus.WithLabelValues(f.countryPath).Set(0)

			locErr = fmt.Errorf("location subnet data: %w", locErr)
		}

		f.mu.Lock()
		defer f.mu.Unlock()

		f.ipv4LocationSubnets, f.ipv6LocationSubnets = ipv4, ipv6
	}()

	go func() {
		defer wg.Done()

		var ipv4, ipv6 countrySubnets
		ipv4, ipv6, ctryErr = resetCountrySubnets(ctx, f.logger, country)

		if ctryErr != nil {
			metrics.GeoIPUpdateStatus.WithLabelValues(f.countryPath).Set(0)

			ctryErr = fmt.Errorf("country subnet data: %w", ctryErr)
		}

		f.mu.Lock()
		defer f.mu.Unlock()

		f.ipv4CountrySubnets, f.ipv6CountrySubnets = ipv4, ipv6
	}()

	wg.Wait()

	return errors.Annotate(errors.Join(ctryErr, locErr), "refreshing: %w")
}

// geoIPFromFile reads the entire content of the file at fn and returns an
// initialized and checked reader.
func geoIPFromFile(fn string) (r *maxminddb.Reader, err error) {
	// #nosec G304 -- Trust the paths to the GeoIP database files that are given
	// from the environment.
	b, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("reading geoip file: %w", err)
	}

	r, err = maxminddb.FromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("parsing geoip file %q: %w", fn, err)
	}

	// Check the reader.
	var v any
	err = r.Lookup(net.IPv4zero, v)
	if err != nil {
		return nil, fmt.Errorf("checking geoip %q: %w", fn, err)
	}

	return r, nil
}
