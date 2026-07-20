package ruleliststorage

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
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

	// IndexStorage is used to get rule list index data.  It must not be nil.
	IndexStorage filterindex.RulelistStorage

	// Logger is used for logging the operation of the storage.  It must not be
	// nil.
	Logger *slog.Logger

	// Metrics are the metrics for the filters in the storage.  It must not be
	// nil.
	Metrics filter.Metrics

	// CacheDir is the path to the directory where the cached rule lists files
	// are stored.  It must not be empty and the directory must exist.
	CacheDir string

	// MaxSize is the maximum size for the content of the single filter.  It
	// must be positive.
	MaxSize datasize.ByteSize

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
	indexStorage filterindex.RulelistStorage
	logger       *slog.Logger
	metrics      filter.Metrics

	// ruleListsMu protects ruleLists.
	//
	// TODO(a.garipov):  Improve serialization of actions or document the
	// supported flows better.
	ruleListsMu *sync.RWMutex

	ruleLists ruleLists

	indexCachePath string
	cacheDir       string

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
	return &Default{
		baseLogger:   c.BaseLogger,
		cacheManager: c.CacheManager,
		clock:        c.Clock,
		errColl:      c.ErrColl,
		indexStorage: c.IndexStorage,
		logger:       c.Logger,
		metrics:      c.Metrics,
		ruleListsMu:  &sync.RWMutex{},

		// Initialized with [Default.RefreshInitial].
		ruleLists: nil,

		indexCachePath: filepath.Join(c.CacheDir, filter.SubDirNameIndex, indexFileNameRuleLists),
		cacheDir:       filepath.Join(c.CacheDir, filter.SubDirNameRuleList),
		staleness:      c.Staleness,
		refreshTimeout: c.RefreshTimeout,
		maxSize:        c.MaxSize,
		resCacheCount:  c.ResultCacheCount,
		cacheEnabled:   c.ResultCacheEnabled,
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
