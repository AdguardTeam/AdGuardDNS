package profiledb

import (
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
)

// Config is the default profile database configuration.
type Config struct {
	// Logger is used for logging the operation of profile database.  It must
	// not be nil.
	Logger *slog.Logger

	// BaseCustomLogger is the base logger used for the custom filters.  It must
	// not be nil.
	BaseCustomLogger *slog.Logger

	// Clock is used to get current time during refreshes.  It must not be nil.
	Clock timeutil.Clock

	// ErrColl is used to collect errors during refreshes.  It must not be nil.
	ErrColl errcoll.Interface

	// Metrics is used for the collection of the user profiles statistics.  It
	// must not be nil.
	Metrics Metrics

	// Storage returns the data for this profile DB.  It must not be nil.
	Storage Storage

	// CacheFilePath is the path to the profile cache file.  If cacheFilePath is
	// the string "none", filesystem cache is disabled.  It must not be empty.
	CacheFilePath string

	// FullSyncIvl is the interval between two full synchronizations with the
	// storage.  It must be positive.
	FullSyncIvl time.Duration

	// FullSyncRetryIvl is the interval between two retries of full
	// synchronizations with the storage.  It must be positive.
	FullSyncRetryIvl time.Duration

	// ResponseSizeEstimate is the estimate of the size of one DNS response for
	// the purposes of custom ratelimiting.  Responses over this estimate are
	// counted as several responses.  It must be positive.
	ResponseSizeEstimate datasize.ByteSize
}
