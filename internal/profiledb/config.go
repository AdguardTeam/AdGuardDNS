package profiledb

import (
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Config is the default profile database configuration.
type Config struct {
	// Logger is used for logging the operation of profile database.  It must
	// not be nil.
	Logger *slog.Logger

	// Clock is used to get current time during refreshes.  It must not be nil.
	Clock timeutil.Clock

	// CustomDomainDB is used to keep track of the data about custom domains and
	// their certificates.  It must not be nil.
	CustomDomainDB CustomDomainDB

	// ErrColl is used to collect errors during refreshes.  It must not be nil.
	ErrColl errcoll.Interface

	// ProfileMetrics is used for the collection of the profile access engine
	// statistics.  It must not be nil.
	ProfileMetrics access.ProfileMetrics

	// Metrics is used for the collection of the user profiles statistics.  It
	// must not be nil.
	Metrics Metrics

	// Storage returns the data for this profile DB.  It must not be nil.
	Storage Storage

	// FileCacheStorage is used for caching profiles.  It must not be nil.
	FileCacheStorage FileCacheStorage

	// CacheFileIvl is the interval between updates of the profile cache file.
	// It must be positive if filesystem cache is enabled, see CacheFilePath.
	CacheFileIvl time.Duration

	// FullSyncIvl is the interval between two full synchronizations with the
	// storage.  It must be positive.
	FullSyncIvl time.Duration

	// FullSyncRetryIvl is the interval between two retries of full
	// synchronizations with the storage.  It must be positive.
	FullSyncRetryIvl time.Duration
}
