package homoglyph

import (
	"log/slog"
	"net/http/cookiejar"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Config is the configuration structure for the homoglyph filter.
//
// TODO(e.burkov):  Add more metrics.
type Config struct {
	// Cloner is used to clone messages taken from filtering-result cache.  It
	// must not be nil.
	Cloner *dnsmsg.Cloner

	// Logger is used for logging the operation of the filter.  It must not be
	// nil.
	Logger *slog.Logger

	// CacheManager is the global cache manager.  It must not be nil.
	CacheManager agdcache.Manager

	// Clock is used for time-related operations.  It must not be nil.
	Clock timeutil.Clock

	// ErrColl is used to collect errors during refreshes.  It must not be nil.
	ErrColl errcoll.Interface

	// Metrics are the metrics for the homoglyph filter.  It must not be nil.
	Metrics filter.Metrics

	// PublicSuffixList is used for obtaining public suffix for specified
	// domain.  It must not be nil.
	PublicSuffixList cookiejar.PublicSuffixList

	// ReplacedResultConstructor is used to create filtering results.  It must
	// not be nil.
	ReplacedResultConstructor *filter.ReplacedResultConstructor

	// Storage is used to obtain the current state of the homoglyph filter
	// index.  It must not be nil.
	Storage filterindex.Storage

	// CachePath is the path to the file containing the cached data.  It must
	// not be empty.
	CachePath string

	// ResultListID is the identifier of the filter list used in the request
	// filtering result.  It must not be empty.
	ResultListID filter.ID

	// Staleness is the time after which the cache file is considered stale.  It
	// should be positive.
	Staleness time.Duration

	// CacheCount is the count of items to keep in the LRU result cache.  It
	// must be greater than zero and less than or equal to [math.MaxInt].
	CacheCount uint64
}
