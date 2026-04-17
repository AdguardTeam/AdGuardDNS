package ruleliststorage

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
)

// Config is the rule list storage configuration.
type Config struct {
	// BaseLogger is the logger to use.  It must not be nil.
	BaseLogger *slog.Logger

	// CacheManager is the global cache manager.  It must not be nil.
	CacheManager agdcache.Manager

	// Clock is used for time-related operations, such as schedule checking.  It
	// must not be nil.
	Clock timeutil.Clock

	// ErrColl is used to collect non-critical and rare errors as well as
	// refresh errors.  It must not be nil.
	ErrColl errcoll.Interface

	// IndexConfig is the rule list index configuration.  It must not be nil.
	IndexConfig *IndexConfig

	// Logger is used for logging the operation of the storage.  It must not be
	// nil.
	Logger *slog.Logger

	// Metrics are the metrics for the filters in the storage.  It must not be
	// nil.
	Metrics filter.Metrics

	// CacheDir is the path to the directory where the cached rule lists files
	// are stored.  It must not be empty and the directory must exist.
	CacheDir string
}

// IndexConfig is the rule list index configuration.
type IndexConfig struct {
	// IndexURL is the URL of the filter index.  It must not be modified after
	// calling [New].  It must not be nil.
	IndexURL *url.URL

	// IndexMaxSize is the maximum size of the downloadable filter index
	// content.  It must be positive.
	IndexMaxSize datasize.ByteSize

	// MaxSize is the maximum size of the content of a single filter index.  It
	// must be positive.
	MaxSize datasize.ByteSize

	// IndexRefreshTimeout is the timeout for the update of the filter index.
	// It must be positive.
	IndexRefreshTimeout time.Duration

	// IndexStaleness is the time after which the cached index file is
	// considered stale.  It must be positive.
	IndexStaleness time.Duration

	// RefreshTimeout is the timeout for the update of a single filter.  It must
	// be positive.
	RefreshTimeout time.Duration

	// Staleness is the time after which the cached filter files are considered
	// stale.  It must be positive.
	Staleness time.Duration

	// ResultCacheCount is the count of items to keep in the LRU result cache of
	// a single filter.  It must be greater than zero and less than or equal to
	// [math.MaxInt].
	ResultCacheCount uint64

	// ResultCacheEnabled enables caching of results of the filters.
	ResultCacheEnabled bool
}

// ruleListData represents a rule list with its update time.
type ruleListData struct {
	// refr is the rule list refreshable, it must not be nil.
	refr *rulelist.Refreshable

	// updTime is the last update time of the rule list data.
	updTime time.Time
}

// ruleLists is convenient alias for an ID to a rule list data mapping.
type ruleLists = map[filter.ID]*ruleListData

// Default is the default rule list storage that stores and refreshes rule
// lists.
type Default struct {
	baseLogger   *slog.Logger
	cacheManager agdcache.Manager
	clock        timeutil.Clock
	errColl      errcoll.Interface
	logger       *slog.Logger
	metrics      filter.Metrics
	refr         *refreshable.Refreshable

	// ruleListsMu protects ruleLists.
	//
	// TODO(a.garipov):  Improve serialization of actions or document the
	// supported flows better.
	ruleListsMu *sync.RWMutex

	ruleLists ruleLists

	cacheDir string

	staleness      time.Duration
	refreshTimeout time.Duration

	maxSize datasize.ByteSize

	resCacheCount uint64
	cacheEnabled  bool
}

// New returns a new default rule list storage ready for initial refresh.  c
// must not be nil.  The storage is not ready for use until
// [Default.RefreshInitial].
func New(c *Config) (s *Default, err error) {
	idxConf := c.IndexConfig

	idxRefr, err := refreshable.New(&refreshable.Config{
		Logger: c.BaseLogger.With(
			slogutil.KeyPrefix, path.Join("filters", string(filterIDRuleListIndex)),
		),
		URL:       idxConf.IndexURL,
		ID:        filterIDRuleListIndex,
		CachePath: filepath.Join(c.CacheDir, filter.SubDirNameIndex, indexFileNameRuleLists),
		Staleness: idxConf.IndexStaleness,
		Timeout:   idxConf.IndexRefreshTimeout,
		MaxSize:   idxConf.IndexMaxSize,
	})
	if err != nil {
		return nil, fmt.Errorf("initializing rule list refresher: %w", err)
	}

	return &Default{
		baseLogger:   c.BaseLogger,
		cacheManager: c.CacheManager,
		clock:        c.Clock,
		errColl:      c.ErrColl,
		logger:       c.Logger,
		metrics:      c.Metrics,
		refr:         idxRefr,
		ruleListsMu:  &sync.RWMutex{},

		// Initialized with [Default.RefreshInitial].
		ruleLists: nil,

		cacheDir:       filepath.Join(c.CacheDir, filter.SubDirNameRuleList),
		staleness:      idxConf.Staleness,
		refreshTimeout: idxConf.RefreshTimeout,
		maxSize:        idxConf.MaxSize,
		resCacheCount:  idxConf.ResultCacheCount,
		cacheEnabled:   idxConf.ResultCacheEnabled,
	}, nil
}

// type check
var _ Storage = (*Default)(nil)

// AppendForListIDs implements the [Storage] interface for *Default.
func (s *Default) AppendForListIDs(
	_ context.Context,
	orig []*rulelist.Refreshable,
	ids []filter.ID,
) (rls []*rulelist.Refreshable) {
	rls = orig

	s.ruleListsMu.RLock()
	defer s.ruleListsMu.RUnlock()

	for _, id := range ids {
		rl := s.ruleLists[id]
		if rl != nil {
			rls = append(rls, rl.refr)
		}
	}

	return rls
}

// HasListID implements the [Storage] interface for *Default.
func (s *Default) HasListID(_ context.Context, id filter.ID) (ok bool) {
	s.ruleListsMu.RLock()
	defer s.ruleListsMu.RUnlock()

	_, ok = s.ruleLists[id]

	return ok
}
