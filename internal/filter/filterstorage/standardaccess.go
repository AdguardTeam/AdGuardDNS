package filterstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/google/renameio/v2"
)

// StandardAccessStorage is the interface for a storage of standard access
// settings.
type StandardAccessStorage interface {
	// Config returns the standard access settings.  conf must not be modified
	// after calling this method.
	Config(ctx context.Context) (conf *access.StandardBlockerConfig, err error)
}

// EmptyStandardAccessStorage is the empty implementation of the
// [StandardAccessStorage] interface.
type EmptyStandardAccessStorage struct{}

// type check
var _ StandardAccessStorage = EmptyStandardAccessStorage{}

// Config implements the [StandardAccessStorage] interface for
// EmptyStandardAccessStorage.  It always returns nil.
func (EmptyStandardAccessStorage) Config(
	_ context.Context,
) (conf *access.StandardBlockerConfig, err error) {
	return nil, nil
}

// StandardAccessConfig is the configuration of a standard access storage for a
// default filter storage.
//
// TODO(e.burkov):  Move to another package, when internal/refreshable is moved
// to golibs.
type StandardAccessConfig struct {
	// BaseLogger is used to log cache loading.
	BaseLogger *slog.Logger

	// Logger is used to log refresh operations.
	Logger *slog.Logger

	// Getter is the storage of standard access settings.  It must not be nil.
	Getter StandardAccessStorage

	// Setter is the standard access to refresh from storage.  It must not be
	// nil.
	Setter access.StandardSetter

	// CacheDir is the directory where the cache files are stored.
	CacheDir string
}

// StandardAccess updates the standard access settings from storage, caching
// them in the cache directory.
type StandardAccess struct {
	getter    StandardAccessStorage
	logger    *slog.Logger
	setter    access.StandardSetter
	latest    *access.StandardBlockerConfig
	cache     *refreshable.Refreshable
	cachePath string
}

// NewStandardAccess creates a new properly initialized standard access.  c must
// be valid.  It uses the latest cached settings if available, use the
// [StandardAccess.Refresh] method to update them.
func NewStandardAccess(
	ctx context.Context,
	c *StandardAccessConfig,
) (s *StandardAccess, err error) {
	cachePath := filepath.Join(c.CacheDir, indexFileNameStandardProfileAccess)

	refr, err := refreshable.New(&refreshable.Config{
		Logger: c.BaseLogger.With(slogutil.KeyPrefix, "standard_access_cache"),
		URL: &url.URL{
			Scheme: urlutil.SchemeFile,
			Path:   cachePath,
		},
		ID: FilterIDStandardProfileAccess,
		// Don't set CachePath, Timeout and MaxSize, since this refreshable is
		// used in file-only mode.  Also don't set Staleness, since it always
		// accepts stale.
	})
	if err != nil {
		return nil, fmt.Errorf("creating refreshable: %w", err)
	}

	s = &StandardAccess{
		getter:    c.Getter,
		logger:    c.Logger,
		setter:    c.Setter,
		cache:     refr,
		cachePath: cachePath,
	}

	err = s.loadFromCache(ctx)
	if err != nil {
		if !errors.Is(err, errors.ErrNoValue) {
			// Don't wrap the error, since it's informative enough as is.
			return nil, err
		}

		s.logger.WarnContext(ctx, "cache is empty")
		s.latest = &access.StandardBlockerConfig{}
	}

	s.setter.SetConfig(s.latest)

	return s, nil
}

// type check
var _ service.Refresher = (*StandardAccess)(nil)

// Refresh implements the [service.Refresher] interface for *StandardAccess.
func (s *StandardAccess) Refresh(ctx context.Context) (err error) {
	s.logger.InfoContext(ctx, "refresh started")
	defer s.logger.InfoContext(ctx, "refresh finished")

	conf, err := s.getter.Config(ctx)
	if err != nil {
		return err
	}

	if conf == nil {
		conf = &access.StandardBlockerConfig{}
	}

	if conf.Equal(s.latest) {
		s.logger.DebugContext(ctx, "no changes")

		return nil
	}

	s.latest = conf
	s.setter.SetConfig(s.latest)

	err = s.writeCache()
	if err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}

	return nil
}

// StandardAccessVersion is the current schema version of the standard access
// settings cache.
//
// NOTE:  Increment this value on every change in [access.StandardBlockerConfig]
// that requires a change in the JSON representation.
const StandardAccessVersion uint = 1

// jsonStandardAccessSettings is the JSON representation of
// [access.StandardBlockerConfig].
type jsonStandardAccessSettings struct {
	AllowedNets          []netutil.Prefix `json:"allowed_nets"`
	BlockedNets          []netutil.Prefix `json:"blocked_nets"`
	AllowedASN           []geoip.ASN      `json:"allowed_asns"`
	BlockedASN           []geoip.ASN      `json:"blocked_asns"`
	BlocklistDomainRules []string         `json:"rules"`
	SchemaVersion        uint             `json:"schema_version"`
}

// standardAccessConfigToJSON converts the standard access settings to the JSON
// representation.
func standardAccessConfigToJSON(conf *access.StandardBlockerConfig) (s *jsonStandardAccessSettings) {
	s = &jsonStandardAccessSettings{
		AllowedNets:          make([]netutil.Prefix, 0, len(conf.AllowedNets)),
		BlockedNets:          make([]netutil.Prefix, 0, len(conf.BlockedNets)),
		AllowedASN:           conf.AllowedASN,
		BlockedASN:           conf.BlockedASN,
		BlocklistDomainRules: conf.BlocklistDomainRules,
		SchemaVersion:        StandardAccessVersion,
	}
	for _, p := range conf.AllowedNets {
		s.AllowedNets = append(s.AllowedNets, netutil.Prefix{Prefix: p})
	}
	for _, p := range conf.BlockedNets {
		s.BlockedNets = append(s.BlockedNets, netutil.Prefix{Prefix: p})
	}

	return s
}

// toInternal converts the JSON representation of the standard access settings
// to the internal one.
func (s *jsonStandardAccessSettings) toInternal() (conf *access.StandardBlockerConfig) {
	return &access.StandardBlockerConfig{
		AllowedNets:          netutil.UnembedPrefixes(s.AllowedNets),
		BlockedNets:          netutil.UnembedPrefixes(s.BlockedNets),
		AllowedASN:           s.AllowedASN,
		BlockedASN:           s.BlockedASN,
		BlocklistDomainRules: s.BlocklistDomainRules,
	}
}

// loadFromCache loads the standard access settings from the cache.
func (s *StandardAccess) loadFromCache(ctx context.Context) (err error) {
	raw, err := s.cache.Refresh(ctx, true)
	if err != nil {
		return fmt.Errorf("loading cache: %w", err)
	}

	err = validate.NotEmptySlice("cache", raw)
	if err != nil {
		// Don't wrap the error, since it's informative enough as is.
		return err
	}

	settings := &jsonStandardAccessSettings{}
	err = json.Unmarshal(raw, settings)
	if err != nil {
		return fmt.Errorf("decoding cache: %w", err)
	}

	v := settings.SchemaVersion
	err = validate.InRange("schema_version", v, StandardAccessVersion, StandardAccessVersion)
	if err != nil {
		return fmt.Errorf("malformed cache: %w", err)
	}

	s.latest = settings.toInternal()

	return nil
}

// writeCache writes the latest standard access settings to the cache.
func (s *StandardAccess) writeCache() (err error) {
	settings := standardAccessConfigToJSON(s.latest)

	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(settings)
	if err != nil {
		return fmt.Errorf("encoding cache: %w", err)
	}

	return renameio.WriteFile(s.cachePath, b.Bytes(), 0o600)
}
