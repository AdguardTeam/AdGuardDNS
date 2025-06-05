package cmd

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/version"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/c2h5oh/datasize"
	"github.com/caarlos0/env/v7"
	"github.com/getsentry/sentry-go"
)

// environment represents the configuration that is kept in the environment.
//
// TODO(e.burkov, a.garipov):  Name variables more consistently.
type environment struct {
	AdultBlockingURL         *urlutil.URL `env:"ADULT_BLOCKING_URL"`
	BackendRateLimitURL      *urlutil.URL `env:"BACKEND_RATELIMIT_URL"`
	BillStatURL              *urlutil.URL `env:"BILLSTAT_URL"`
	BlockedServiceIndexURL   *urlutil.URL `env:"BLOCKED_SERVICE_INDEX_URL"`
	ConsulAllowlistURL       *urlutil.URL `env:"CONSUL_ALLOWLIST_URL"`
	ConsulDNSCheckKVURL      *urlutil.URL `env:"CONSUL_DNSCHECK_KV_URL"`
	ConsulDNSCheckSessionURL *urlutil.URL `env:"CONSUL_DNSCHECK_SESSION_URL"`
	DNSCheckRemoteKVURL      *urlutil.URL `env:"DNSCHECK_REMOTEKV_URL"`
	FilterIndexURL           *urlutil.URL `env:"FILTER_INDEX_URL,notEmpty"`
	GeneralSafeSearchURL     *urlutil.URL `env:"GENERAL_SAFE_SEARCH_URL"`
	LinkedIPTargetURL        *urlutil.URL `env:"LINKED_IP_TARGET_URL"`
	NewRegDomainsURL         *urlutil.URL `env:"NEW_REG_DOMAINS_URL"`
	ProfilesURL              *urlutil.URL `env:"PROFILES_URL"`
	RuleStatURL              *urlutil.URL `env:"RULESTAT_URL"`
	SafeBrowsingURL          *urlutil.URL `env:"SAFE_BROWSING_URL"`
	YoutubeSafeSearchURL     *urlutil.URL `env:"YOUTUBE_SAFE_SEARCH_URL"`

	BackendRateLimitAPIKey string `env:"BACKEND_RATELIMIT_API_KEY"`
	BillStatAPIKey         string `env:"BILLSTAT_API_KEY"`
	ConfPath               string `env:"CONFIG_PATH" envDefault:"./config.yaml"`
	DNSCheckRemoteKVAPIKey string `env:"DNSCHECK_REMOTEKV_API_KEY"`
	FilterCachePath        string `env:"FILTER_CACHE_PATH" envDefault:"./filters/"`
	GeoIPASNPath           string `env:"GEOIP_ASN_PATH" envDefault:"./asn.mmdb"`
	GeoIPCountryPath       string `env:"GEOIP_COUNTRY_PATH" envDefault:"./country.mmdb"`
	LogFormat              string `env:"LOG_FORMAT" envDefault:"text"`
	ProfilesAPIKey         string `env:"PROFILES_API_KEY"`
	ProfilesCachePath      string `env:"PROFILES_CACHE_PATH" envDefault:"./profilecache.pb"`
	QueryLogPath           string `env:"QUERYLOG_PATH" envDefault:"./querylog.jsonl"`
	RedisAddr              string `env:"REDIS_ADDR"`
	RedisKeyPrefix         string `env:"REDIS_KEY_PREFIX" envDefault:"agdns"`
	SSLKeyLogFile          string `env:"SSL_KEY_LOG_FILE"`
	SentryDSN              string `env:"SENTRY_DSN" envDefault:"stderr"`
	// TODO(a.garipov):  Consider renaming to "WEB_STATIC_PATH" or something
	// similar.
	WebStaticDir string `env:"WEB_STATIC_DIR"`

	ListenAddr net.IP `env:"LISTEN_ADDR" envDefault:"127.0.0.1"`

	ProfilesMaxRespSize datasize.ByteSize `env:"PROFILES_MAX_RESP_SIZE" envDefault:"64MB"`

	RedisIdleTimeout timeutil.Duration `env:"REDIS_IDLE_TIMEOUT" envDefault:"30s"`

	// TODO(a.garipov):  Rename to DNSCHECK_CACHE_KV_COUNT?
	DNSCheckCacheKVSize int `env:"DNSCHECK_CACHE_KV_SIZE"`
	RedisMaxActive      int `env:"REDIS_MAX_ACTIVE" envDefault:"10"`
	RedisMaxIdle        int `env:"REDIS_MAX_IDLE" envDefault:"3"`

	ListenPort uint16 `env:"LISTEN_PORT" envDefault:"8181"`
	RedisPort  uint16 `env:"REDIS_PORT" envDefault:"6379"`

	Verbosity uint8 `env:"VERBOSE" envDefault:"0"`

	AdultBlockingEnabled     strictBool `env:"ADULT_BLOCKING_ENABLED" envDefault:"1"`
	LogTimestamp             strictBool `env:"LOG_TIMESTAMP" envDefault:"1"`
	NewRegDomainsEnabled     strictBool `env:"NEW_REG_DOMAINS_ENABLED" envDefault:"1"`
	SafeBrowsingEnabled      strictBool `env:"SAFE_BROWSING_ENABLED" envDefault:"1"`
	BlockedServiceEnabled    strictBool `env:"BLOCKED_SERVICE_ENABLED" envDefault:"1"`
	GeneralSafeSearchEnabled strictBool `env:"GENERAL_SAFE_SEARCH_ENABLED" envDefault:"1"`
	YoutubeSafeSearchEnabled strictBool `env:"YOUTUBE_SAFE_SEARCH_ENABLED" envDefault:"1"`
	WebStaticDirEnabled      strictBool `env:"WEB_STATIC_DIR_ENABLED" envDefault:"0"`
}

// parseEnvironment reads the configuration.
func parseEnvironment() (envs *environment, err error) {
	envs = &environment{}
	err = env.Parse(envs)
	if err != nil {
		return nil, fmt.Errorf("parsing environments: %w", err)
	}

	return envs, nil
}

// type check
var _ validate.Interface = (*environment)(nil)

// Validate implements the [validate.Interface] interface for *environment.
func (envs *environment) Validate() (err error) {
	var errs []error

	errs = envs.validateHTTPURLs(errs)

	if s := envs.FilterIndexURL.Scheme; !strings.EqualFold(s, urlutil.SchemeFile) &&
		!urlutil.IsValidHTTPURLScheme(s) {
		errs = append(errs, fmt.Errorf(
			"%s: not a valid http(s) url or file uri",
			"FILTER_INDEX_URL",
		))
	}

	err = envs.validateWebStaticDir()
	if err != nil {
		errs = append(errs, fmt.Errorf("WEB_STATIC_DIR: %w", err))
	}

	_, err = slogutil.NewFormat(envs.LogFormat)
	if err != nil {
		errs = append(errs, fmt.Errorf("LOG_FORMAT: %w", err))
	}

	_, err = slogutil.VerbosityToLevel(envs.Verbosity)
	if err != nil {
		errs = append(errs, fmt.Errorf("VERBOSE: %w", err))
	}

	return errors.Join(errs...)
}

// urlEnvData is a helper struct for validation of URLs set in environment
// variables.
type urlEnvData struct {
	url        *urlutil.URL
	name       string
	isRequired bool
}

// validateHTTPURLs appends validation errors to the given errs if HTTP(S) URLs
// in environment variables are invalid.  All errors are appended to errs and
// returned as res.
func (envs *environment) validateHTTPURLs(errs []error) (res []error) {
	httpOnlyURLs := []*urlEnvData{{
		url:        envs.AdultBlockingURL,
		name:       "ADULT_BLOCKING_URL",
		isRequired: bool(envs.AdultBlockingEnabled),
	}, {
		url:        envs.BlockedServiceIndexURL,
		name:       "BLOCKED_SERVICE_INDEX_URL",
		isRequired: bool(envs.BlockedServiceEnabled),
	}, {
		url:        envs.ConsulDNSCheckKVURL,
		name:       "CONSUL_DNSCHECK_KV_URL",
		isRequired: envs.ConsulDNSCheckKVURL != nil,
	}, {
		url:        envs.ConsulDNSCheckSessionURL,
		name:       "CONSUL_DNSCHECK_SESSION_URL",
		isRequired: envs.ConsulDNSCheckSessionURL != nil,
	}, {
		url:        envs.GeneralSafeSearchURL,
		name:       "GENERAL_SAFE_SEARCH_URL",
		isRequired: bool(envs.GeneralSafeSearchEnabled),
	}, {
		url:        envs.LinkedIPTargetURL,
		name:       "LINKED_IP_TARGET_URL",
		isRequired: false,
	}, {
		url:        envs.NewRegDomainsURL,
		name:       "NEW_REG_DOMAINS_URL",
		isRequired: bool(envs.NewRegDomainsEnabled),
	}, {
		url:        envs.RuleStatURL,
		name:       "RULESTAT_URL",
		isRequired: false,
	}, {
		url:        envs.SafeBrowsingURL,
		name:       "SAFE_BROWSING_URL",
		isRequired: bool(envs.SafeBrowsingEnabled),
	}, {
		url:        envs.YoutubeSafeSearchURL,
		name:       "YOUTUBE_SAFE_SEARCH_URL",
		isRequired: bool(envs.YoutubeSafeSearchEnabled),
	}}

	res = errs
	for _, urlData := range httpOnlyURLs {
		if !urlData.isRequired {
			continue
		}

		var u *url.URL
		if urlData.url != nil {
			u = &urlData.url.URL
		}

		err := urlutil.ValidateHTTPURL(u)
		if err != nil {
			res = append(res, fmt.Errorf("env %s: %w", urlData.name, err))
		}
	}

	return res
}

// validateWebStaticDir returns an error if the WEB_STATIC_DIR environment
// variable contains an invalid value.
func (envs *environment) validateWebStaticDir() (err error) {
	if !envs.WebStaticDirEnabled {
		return nil
	}

	dir := envs.WebStaticDir
	if dir == "" {
		return errors.ErrEmptyValue
	}

	// Use a best-effort check to make sure the directory exists.
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}

	if !fi.IsDir() {
		return errors.Error("not a directory")
	}

	return nil
}

// validateFromValidConfig returns an error if environment variables that depend
// on configuration properties contain errors.  conf is expected to be valid.
func (envs *environment) validateFromValidConfig(conf *configuration) (err error) {
	var errs []error

	switch typ := conf.Check.KV.Type; typ {
	case kvModeBackend:
		errs = envs.validateBackendKV(errs)
	case kvModeCache:
		errs = envs.validateCache(errs)
	case kvModeRedis:
		errs = envs.validateRedis(errs)
	default:
		// Probably consul.
	}

	if conf.isProfilesEnabled() {
		errs = envs.validateProfilesURLs(errs)

		err = validate.NoGreaterThan(
			"PROFILES_MAX_RESP_SIZE",
			envs.ProfilesMaxRespSize,
			math.MaxInt,
		)
		if err != nil {
			errs = append(errs, err)
		}
	}

	errs = envs.validateRateLimitURLs(conf, errs)

	return errors.Join(errs...)
}

// validateCache appends validation errors to the given errs if environment
// variables for KV Cache contain errors.
func (envs *environment) validateCache(errs []error) (res []error) {
	res = errs

	err := validate.Positive("env DNSCHECK_CACHE_KV_SIZE", envs.DNSCheckCacheKVSize)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		res = append(res, err)
	}

	return res
}

// validateRedis appends validation errors to the given errs if environment
// variables for Redis contain errors.
func (envs *environment) validateRedis(errs []error) (res []error) {
	res = errs

	if err := validate.NotEmpty("env REDIS_ADDR", envs.RedisAddr); err != nil {
		// Don't wrap the error, because it's informative enough as is.
		res = append(res, err)
	}

	if err := validate.Positive("env REDIS_IDLE_TIMEOUT", envs.RedisIdleTimeout); err != nil {
		// Don't wrap the error, because it's informative enough as is.
		res = append(res, err)
	}

	if err := validate.NotNegative("env REDIS_MAX_ACTIVE", envs.RedisMaxActive); err != nil {
		// Don't wrap the error, because it's informative enough as is.
		res = append(res, err)
	}

	if err := validate.NotNegative("env REDIS_MAX_IDLE", envs.RedisMaxIdle); err != nil {
		// Don't wrap the error, because it's informative enough as is.
		res = append(res, err)
	}

	return res
}

// validateBackendKV appends validation errors to the given errs if environment
// variables for a backend key-value store contain errors.
func (envs *environment) validateBackendKV(errs []error) (res []error) {
	res = errs

	var u *url.URL
	if envs.DNSCheckRemoteKVURL != nil {
		u = &envs.DNSCheckRemoteKVURL.URL
	}

	err := urlutil.ValidateGRPCURL(u)
	if err != nil {
		res = append(res, fmt.Errorf("env DNSCHECK_REMOTEKV_URL: %w", err))
	}

	return res
}

// validateProfilesURLs appends validation errors to the given errs if profiles
// URLs in environment variables are invalid.
func (envs *environment) validateProfilesURLs(errs []error) (res []error) {
	res = errs

	grpcOnlyURLs := []*urlEnvData{{
		url:        envs.BillStatURL,
		name:       "BILLSTAT_URL",
		isRequired: true,
	}, {
		url:        envs.ProfilesURL,
		name:       "PROFILES_URL",
		isRequired: true,
	}}

	for _, urlData := range grpcOnlyURLs {
		if !urlData.isRequired {
			continue
		}

		var u *url.URL
		if urlData.url != nil {
			u = &urlData.url.URL
		}

		err := urlutil.ValidateGRPCURL(u)
		if err != nil {
			res = append(res, fmt.Errorf("env %s: %w", urlData.name, err))
		}
	}

	return res
}

// validateRateLimitURLs appends validation errors to the given errs if rate
// limit URLs in environment variables are invalid.
func (envs *environment) validateRateLimitURLs(
	conf *configuration,
	errs []error,
) (withURLs []error) {
	rlURL := envs.BackendRateLimitURL
	rlEnv := "BACKEND_RATELIMIT_URL"
	validateFunc := urlutil.ValidateGRPCURL

	if conf.RateLimit.Allowlist.Type == rlAllowlistTypeConsul {
		rlURL = envs.ConsulAllowlistURL
		rlEnv = "CONSUL_ALLOWLIST_URL"
		validateFunc = urlutil.ValidateHTTPURL
	}

	var u *url.URL
	if rlURL != nil {
		u = &rlURL.URL
	}

	err := validateFunc(u)
	if err != nil {
		return append(errs, fmt.Errorf("env %s: %w", rlEnv, err))
	}

	return errs
}

// buildErrColl builds and returns an error collector from environment.
// baseLogger must not be nil.
func (envs *environment) buildErrColl(
	baseLogger *slog.Logger,
) (errColl errcoll.Interface, err error) {
	dsn := envs.SentryDSN
	if dsn == "stderr" {
		return errcoll.NewWriterErrorCollector(os.Stderr), nil
	}

	cli, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:              dsn,
		AttachStacktrace: true,
		Release:          version.Version(),
	})
	if err != nil {
		return nil, err
	}

	l := baseLogger.With(slogutil.KeyPrefix, "sentry_errcoll")

	return errcoll.NewSentryErrorCollector(cli, l), nil
}

// debugConf returns a debug HTTP service configuration from environment.
func (envs *environment) debugConf(
	dnsDB dnsdb.Interface,
	logger *slog.Logger,
) (conf *debugsvc.Config) {
	// TODO(a.garipov): Simplify the config if these are guaranteed to always be
	// the same.
	addr := netutil.JoinHostPort(envs.ListenAddr.String(), envs.ListenPort)

	// TODO(a.garipov): Consider other ways of making the DNSDB API fully
	// optional.
	var dnsDBAddr string
	var dnsDBHdlr http.Handler
	if h, ok := dnsDB.(http.Handler); ok {
		dnsDBAddr = addr
		dnsDBHdlr = h
	} else {
		dnsDBAddr = ""
		dnsDBHdlr = http.HandlerFunc(http.NotFound)
	}

	conf = &debugsvc.Config{
		DNSDBHandler:   dnsDBHdlr,
		Logger:         logger.With(slogutil.KeyPrefix, "debugsvc"),
		DNSDBAddr:      dnsDBAddr,
		APIAddr:        addr,
		PprofAddr:      addr,
		PrometheusAddr: addr,
	}

	return conf
}

// strictBool is a type for booleans that are parsed from the environment more
// strictly than the usual bool.  It only accepts "0" and "1" as valid values.
type strictBool bool

// UnmarshalText implements the encoding.TextUnmarshaler interface for
// *strictBool.
func (sb *strictBool) UnmarshalText(b []byte) (err error) {
	if len(b) == 1 {
		switch b[0] {
		case '0':
			*sb = false

			return nil
		case '1':
			*sb = true

			return nil
		default:
			// Go on and return an error.
		}
	}

	return fmt.Errorf("invalid value %q, supported: %q, %q", b, "0", "1")
}
