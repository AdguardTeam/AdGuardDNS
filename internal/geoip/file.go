package geoip

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/bluele/gcache"
	"github.com/oschwald/maxminddb-golang"
)

// File Database

// FileConfig is the file-based GeoIP configuration structure.
type FileConfig struct {
	// ErrColl is the error collector that is used to report errors.
	ErrColl agd.ErrorCollector

	// ASNPath is the path to the GeoIP database of ASNs.
	ASNPath string

	// CountryPath is the path to the GeoIP database of countries.
	CountryPath string

	// HostCacheSize is how many lookups are cached by hostname.  Zero means no
	// host caching is performed.
	HostCacheSize int

	// IPCacheSize is how many lookups are cached by IP address.
	IPCacheSize int
}

// File is a file implementation of [geoip.Interface].
type File struct {
	errColl agd.ErrorCollector

	// mu protects asn, country, country subnet maps, and caches against
	// simultaneous access during a refresh.
	mu *sync.RWMutex

	asn     *maxminddb.Reader
	country *maxminddb.Reader

	// TODO(a.garipov): Consider switching fully to the country ASN method and
	// removing these.
	//
	// See AGDNS-710.
	ipv4CountrySubnets countrySubnets
	ipv6CountrySubnets countrySubnets

	ipv4TopASNSubnets asnSubnets
	ipv6TopASNSubnets asnSubnets

	ipCache   gcache.Cache
	hostCache gcache.Cache

	asnPath     string
	countryPath string

	ipCacheSize   int
	hostCacheSize int
}

// countrySubnets is a country-to-subnet mapping.
type countrySubnets map[agd.Country]netip.Prefix

// asnSubnets is an ASN-to-subnet mapping.
type asnSubnets map[agd.ASN]netip.Prefix

// NewFile returns a new GeoIP database that reads information from a file.
func NewFile(c *FileConfig) (f *File, err error) {
	f = &File{
		errColl: c.ErrColl,

		mu: &sync.RWMutex{},

		asnPath:     c.ASNPath,
		countryPath: c.CountryPath,

		ipCacheSize:   c.IPCacheSize,
		hostCacheSize: c.HostCacheSize,
	}

	// TODO(a.garipov): Consider adding software module ID into the contexts and
	// adding base contexts.
	ctx := context.Background()
	err = f.Refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("initial refresh: %w", err)
	}

	return f, nil
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

		return *(*[3]byte)(a[:])
	}

	a := ip.As16()

	return *(*[7]byte)(a[:])
}

// type check
var _ Interface = (*File)(nil)

// SubnetByLocation implements the Interface interface for *File.  fam must be
// either [netutil.AddrFamilyIPv4] or [netutil.AddrFamilyIPv6].
//
// The process of the subnet selection is as follows:
//
//  1. A list of the most common ASNs, including the top ASN for each country,
//     is pre-generated from the statistics data.  See file asntops_generate.go
//     and its output, asntops.go.
//
//  2. During the server startup, File scans through the provided GeoIP database
//     files searching for the fitting subnets for ASNs and countries.  See
//     resetCountrySubnets and resetTopASNSubnets.
//
//  3. If asn is found within the list of the most used ASNs, its subnet is
//     returned.  If not, the top ASN for the provided country is chosen and its
//     subnet is returned.  If the information about the most used ASNs is not
//     available, the first subnet from the country that is broad enough (see
//     resetCountrySubnets) is chosen.
func (f *File) SubnetByLocation(
	c agd.Country,
	asn agd.ASN,
	fam netutil.AddrFamily,
) (n netip.Prefix, err error) {
	// TODO(a.garipov): Thoroughly cover with tests.

	var topASNSubnets asnSubnets
	var ctrySubnets countrySubnets

	f.mu.RLock()
	defer f.mu.RUnlock()

	switch fam {
	case netutil.AddrFamilyIPv4:
		topASNSubnets = f.ipv4TopASNSubnets
		ctrySubnets = f.ipv4CountrySubnets
	case netutil.AddrFamilyIPv6:
		topASNSubnets = f.ipv6TopASNSubnets
		ctrySubnets = f.ipv6CountrySubnets
	default:
		panic(fmt.Errorf("geoip: unsupported addr fam %s", fam))
	}

	var ok bool
	if n, ok = topASNSubnets[asn]; ok {
		return n, nil
	} else if asn, ok = countryTopASNs[c]; ok {
		// Technically, if there is an entry in countryTopASNs then that entry
		// also always exists in topASNSubnets, but let's be defensive about it.
		if n, ok = topASNSubnets[asn]; ok {
			return n, nil
		}
	}

	if n, ok = ctrySubnets[c]; ok {
		return n, nil
	}

	return netutil.ZeroPrefix(fam), nil
}

// Data implements the Interface interface for *File.  If ip is netip.Addr{},
// Data tries to lookup and return the data based on host, unless it's empty.
func (f *File) Data(host string, ip netip.Addr) (l *agd.Location, err error) {
	if ip == (netip.Addr{}) {
		return f.dataByHost(host), nil
	} else if ip.Is4In6() {
		// This can really only happen when querying data for ECS addresses,
		// since the remote IP address is normalized in dnssvc.ipFromNetAddr.
		// Normalize here, since we use SkipAliasedNetworks in file scanning.
		ip = netip.AddrFrom4(ip.As4())
	}

	cacheKey := ipToCacheKey(ip)
	locVal, err := f.ipCache.Get(cacheKey)
	if err == nil {
		metrics.GeoIPCacheLookupsHits.Inc()

		return locVal.(*agd.Location), nil
	} else if !errors.Is(err, gcache.KeyNotFoundError) {
		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("getting from ip cache: %w", err))
	}

	metrics.GeoIPCacheLookupsMisses.Inc()

	f.mu.RLock()
	defer f.mu.RUnlock()

	asn, err := f.lookupASN(ip)
	if err != nil {
		return nil, fmt.Errorf("looking up asn: %w", err)
	}

	ctry, cont, err := f.lookupCtry(ip)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	l = &agd.Location{
		Country:   ctry,
		Continent: cont,
		ASN:       asn,
	}

	f.setCaches(host, cacheKey, l)

	return l, nil
}

// dataByHost returns GeoIP data that has been cached previously.
func (f *File) dataByHost(host string) (l *agd.Location) {
	locVal, err := f.hostCache.Get(host)
	if err != nil {
		if errors.Is(err, gcache.KeyNotFoundError) {
			metrics.GeoIPHostCacheLookupsMisses.Inc()

			return nil
		}

		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("getting from host cache: %w", err))
	}

	metrics.GeoIPHostCacheLookupsHits.Inc()

	return locVal.(*agd.Location)
}

// asnResult is used to retrieve autonomous system number data from a GeoIP
// reader.
type asnResult struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
}

// lookupASN looks up and returns the autonomous system number part of the GeoIP
// data for ip.
func (f *File) lookupASN(ip netip.Addr) (asn agd.ASN, err error) {
	// TODO(a.garipov): Remove AsSlice if oschwald/maxminddb-golang#88 is done.
	var res asnResult
	err = f.asn.Lookup(ip.AsSlice(), &res)
	if err != nil {
		return 0, fmt.Errorf("looking up asn: %w", err)
	}

	return agd.ASN(res.ASN), nil
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
}

// lookupCtry looks up and returns the country and continent parts of the GeoIP
// data for ip.
func (f *File) lookupCtry(ip netip.Addr) (ctry agd.Country, cont agd.Continent, err error) {
	// TODO(a.garipov): Remove AsSlice if oschwald/maxminddb-golang#88 is done.
	var res countryResult
	err = f.country.Lookup(ip.AsSlice(), &res)
	if err != nil {
		return ctry, cont, fmt.Errorf("looking up country: %w", err)
	}

	ctry, err = agd.NewCountry(res.Country.ISOCode)
	if err != nil {
		return ctry, cont, fmt.Errorf("converting country: %w", err)
	}

	cont, err = agd.NewContinent(res.Continent.Code)
	if err != nil {
		return ctry, cont, fmt.Errorf("converting continent: %w", err)
	}

	return ctry, cont, nil
}

// setCaches sets the GeoIP data into the caches.
func (f *File) setCaches(host string, ipCacheKey any, l *agd.Location) {
	err := f.ipCache.Set(ipCacheKey, l)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("setting ip cache: %w", err))
	}

	if host == "" {
		return
	}

	err = f.hostCache.Set(host, l)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("setting host cache: %w", err))
	}
}

// type check
var _ agd.Refresher = (*File)(nil)

// Refresh implements the agd.Refresher interface for *File.  It reopens the
// GeoIP database files.
func (f *File) Refresh(_ context.Context) (err error) {
	var wg sync.WaitGroup
	wg.Add(2)

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

	var asnErr, ctryErr error

	go func() {
		defer wg.Done()

		var ipv4, ipv6 asnSubnets
		ipv4, ipv6, asnErr = resetTopASNSubnets(asn)

		if asnErr != nil {
			metrics.GeoIPUpdateStatus.WithLabelValues(f.asnPath).Set(0)

			asnErr = fmt.Errorf("resetting geoip: top asn subnet data: %w", asnErr)
		}

		f.mu.Lock()
		defer f.mu.Unlock()

		f.ipv4TopASNSubnets, f.ipv6TopASNSubnets = ipv4, ipv6
	}()

	go func() {
		defer wg.Done()

		var ipv4, ipv6 countrySubnets
		ipv4, ipv6, ctryErr = resetCountrySubnets(country)

		if ctryErr != nil {
			metrics.GeoIPUpdateStatus.WithLabelValues(f.countryPath).Set(0)

			ctryErr = fmt.Errorf("resetting geoip: country subnet data: %w", ctryErr)
		}

		f.mu.Lock()
		defer f.mu.Unlock()

		f.ipv4CountrySubnets, f.ipv6CountrySubnets = ipv4, ipv6
	}()

	wg.Wait()

	if asnErr != nil {
		return asnErr
	}
	if ctryErr != nil {
		return ctryErr
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	metrics.GeoIPUpdateTime.WithLabelValues(f.asnPath).SetToCurrentTime()
	metrics.GeoIPUpdateStatus.WithLabelValues(f.asnPath).Set(1)
	metrics.GeoIPUpdateTime.WithLabelValues(f.countryPath).SetToCurrentTime()
	metrics.GeoIPUpdateStatus.WithLabelValues(f.countryPath).Set(1)

	f.asn, f.country = asn, country

	hostCacheBuilder := gcache.New(f.hostCacheSize)
	if f.hostCacheSize != 0 {
		hostCacheBuilder.LRU()
	}

	f.hostCache = hostCacheBuilder.Build()
	f.ipCache = gcache.New(f.ipCacheSize).LRU().Build()

	return nil
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
