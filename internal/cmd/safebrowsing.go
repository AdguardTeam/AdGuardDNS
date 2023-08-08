package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Safe-browsing and adult-blocking configuration

// safeBrowsingConfig is the configuration for one of the safe browsing filters.
type safeBrowsingConfig struct {
	// BlockHost is the hostname with which to respond to any requests that
	// match the filter.
	//
	// TODO(a.garipov): Consider replacing with a list of IPv4 and IPv6
	// addresses.
	BlockHost string `yaml:"block_host"`

	// CacheSize is the size of the response cache, in entries.
	CacheSize int `yaml:"cache_size"`

	// CacheTTL is the TTL of the response cache.
	CacheTTL timeutil.Duration `yaml:"cache_ttl"`

	// RefreshIvl defines how often AdGuard DNS refreshes the filter.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`
}

// toInternal converts c to the safe browsing filter configuration for the
// filter storage of the DNS server.  c is assumed to be valid.
func (c *safeBrowsingConfig) toInternal(
	errColl agd.ErrorCollector,
	resolver agdnet.Resolver,
	id agd.FilterListID,
	url *agdhttp.URL,
	cacheDir string,
	maxSize int64,
) (fltConf *hashprefix.FilterConfig, err error) {
	hashes, err := hashprefix.NewStorage("")
	if err != nil {
		return nil, err
	}

	return &hashprefix.FilterConfig{
		Hashes:          hashes,
		URL:             netutil.CloneURL(&url.URL),
		ErrColl:         errColl,
		Resolver:        resolver,
		ID:              id,
		CachePath:       filepath.Join(cacheDir, string(id)),
		ReplacementHost: c.BlockHost,
		Staleness:       c.RefreshIvl.Duration,
		CacheTTL:        c.CacheTTL.Duration,
		CacheSize:       c.CacheSize,
		MaxSize:         maxSize,
	}, nil
}

// validate returns an error if the safe browsing filter configuration is
// invalid.
func (c *safeBrowsingConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.BlockHost == "":
		return errors.Error("no block_host")
	case c.CacheSize <= 0:
		return newMustBePositiveError("cache_size", c.CacheSize)
	case c.CacheTTL.Duration <= 0:
		return newMustBePositiveError("cache_ttl", c.CacheTTL)
	case c.RefreshIvl.Duration <= 0:
		return newMustBePositiveError("refresh_interval", c.RefreshIvl)
	default:
		return nil
	}
}

// setupHashPrefixFilter creates and returns a hash-prefix filter as well as
// starts and registers its refresher in the signal handler.
func setupHashPrefixFilter(
	conf *safeBrowsingConfig,
	resolver *agdnet.CachingResolver,
	id agd.FilterListID,
	url *agdhttp.URL,
	cachePath string,
	maxSize int64,
	sigHdlr signalHandler,
	errColl agd.ErrorCollector,
) (strg *hashprefix.Storage, flt *hashprefix.Filter, err error) {
	fltConf, err := conf.toInternal(errColl, resolver, id, url, cachePath, maxSize)
	if err != nil {
		return nil, nil, fmt.Errorf("configuring hash prefix filter %s: %w", id, err)
	}

	flt, err = hashprefix.NewFilter(fltConf)
	if err != nil {
		return nil, nil, fmt.Errorf("creating hash prefix filter %s: %w", id, err)
	}

	refr := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context:             ctxWithDefaultTimeout,
		Refresher:           flt,
		ErrColl:             errColl,
		Name:                string(id),
		Interval:            fltConf.Staleness,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})
	err = refr.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("starting refresher for hash prefix filter %s: %w", id, err)
	}

	sigHdlr.add(refr)

	return fltConf.Hashes, flt, nil
}
