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
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/consulkv"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/rediskv"
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
	CategoryFilterIndexURL   *urlutil.URL `env:"CATEGORY_FILTER_INDEX_URL"`
	ConsulAllowlistURL       *urlutil.URL `env:"CONSUL_ALLOWLIST_URL"`
	ConsulDNSCheckKVURL      *urlutil.URL `env:"CONSUL_DNSCHECK_KV_URL"`
	ConsulDNSCheckSessionURL *urlutil.URL `env:"CONSUL_DNSCHECK_SESSION_URL"`
	CustomDomainsURL         *urlutil.URL `env:"CUSTOM_DOMAINS_URL"`
	DNSCheckRemoteKVURL      *urlutil.URL `env:"DNSCHECK_REMOTEKV_URL"`
	FilterIndexURL           *urlutil.URL `env:"FILTER_INDEX_URL,notEmpty"`
	GeneralSafeSearchURL     *urlutil.URL `env:"GENERAL_SAFE_SEARCH_URL"`
	LinkedIPTargetURL        *urlutil.URL `env:"LINKED_IP_TARGET_URL"`
	NewRegDomainsURL         *urlutil.URL `env:"NEW_REG_DOMAINS_URL"`
	ProfilesURL              *urlutil.URL `env:"PROFILES_URL"`
	RuleStatURL              *urlutil.URL `env:"RULESTAT_URL"`
	SafeBrowsingURL          *urlutil.URL `env:"SAFE_BROWSING_URL"`
	SessionTicketURL         *urlutil.URL `env:"SESSION_TICKET_URL"`
	StandardAccessURL        *urlutil.URL `env:"STANDARD_ACCESS_URL"`
	YoutubeSafeSearchURL     *urlutil.URL `env:"YOUTUBE_SAFE_SEARCH_URL"`

	BackendRateLimitAPIKey string `env:"BACKEND_RATELIMIT_API_KEY"`
	BillStatAPIKey         string `env:"BILLSTAT_API_KEY"`
	ConfPath               string `env:"CONFIG_PATH" envDefault:"./config.yaml"`
	CrashOutputDir         string `env:"CRASH_OUTPUT_DIR"`
	CrashOutputPrefix      string `env:"CRASH_OUTPUT_PREFIX" envDefault:"agdns"`
	CustomDomainsAPIKey    string `env:"CUSTOM_DOMAINS_API_KEY"`
	CustomDomainsCachePath string `env:"CUSTOM_DOMAINS_CACHE_PATH"`
	DNSCheckKVType         string `env:"DNSCHECK_KV_TYPE"`
	DNSCheckRemoteKVAPIKey string `env:"DNSCHECK_REMOTEKV_API_KEY"`
	FilterCachePath        string `env:"FILTER_CACHE_PATH" envDefault:"./filters/"`
	GeoIPASNPath           string `env:"GEOIP_ASN_PATH" envDefault:"./asn.mmdb"`
	GeoIPCountryPath       string `env:"GEOIP_COUNTRY_PATH" envDefault:"./country.mmdb"`
	LogFormat              string `env:"LOG_FORMAT" envDefault:"text"`
	NodeName               string `env:"NODE_NAME,notEmpty"`
	ProfilesAPIKey         string `env:"PROFILES_API_KEY"`
	ProfilesCachePath      string `env:"PROFILES_CACHE_PATH" envDefault:"./profilecache.pb"`
	QueryLogPath           string `env:"QUERYLOG_PATH" envDefault:"./querylog.jsonl"`
	RateLimitAllowlistType string `env:"RATELIMIT_ALLOWLIST_TYPE"`
	RedisKeyPrefix         string `env:"REDIS_KEY_PREFIX" envDefault:"agdns"`
	SSLKeyLogFile          string `env:"SSL_KEY_LOG_FILE"`
	SentryDSN              string `env:"SENTRY_DSN" envDefault:"stderr"`
	SessionTicketAPIKey    string `env:"SESSION_TICKET_API_KEY"`
	SessionTicketCachePath string `env:"SESSION_TICKET_CACHE_PATH"`
	SessionTicketIndexName string `env:"SESSION_TICKET_INDEX_NAME"`
	SessionTicketType      string `env:"SESSION_TICKET_TYPE"`
	StandardAccessAPIKey   string `env:"STANDARD_ACCESS_API_KEY"`
	StandardAccessType     string `env:"STANDARD_ACCESS_TYPE"`

	// TODO(a.garipov):  Consider renaming to "WEB_STATIC_PATH" or something
	// similar.
	WebStaticDir string `env:"WEB_STATIC_DIR"`

	ListenAddr net.IP `env:"LISTEN_ADDR" envDefault:"127.0.0.1"`

	ProfilesMaxRespSize datasize.ByteSize `env:"PROFILES_MAX_RESP_SIZE" envDefault:"64MB"`

	CustomDomainsRefreshIvl  timeutil.Duration `env:"CUSTOM_DOMAINS_REFRESH_INTERVAL"`
	DNSCheckKVTTL            timeutil.Duration `env:"DNSCHECK_KV_TTL"`
	ProfilesCacheIvl         timeutil.Duration `env:"PROFILES_CACHE_INTERVAL"`
	SessionTicketRefreshIvl  timeutil.Duration `env:"SESSION_TICKET_REFRESH_INTERVAL"`
	StandardAccessRefreshIvl timeutil.Duration `env:"STANDARD_ACCESS_REFRESH_INTERVAL"`
	StandardAccessTimeout    timeutil.Duration `env:"STANDARD_ACCESS_TIMEOUT"`

	// TODO(a.garipov):  Rename to DNSCHECK_CACHE_KV_COUNT?
	DNSCheckCacheKVSize int `env:"DNSCHECK_CACHE_KV_SIZE"`
	MaxThreads          int `env:"MAX_THREADS"`

	QueryLogSemaphoreLimit uint `env:"QUERYLOG_SEMAPHORE_LIMIT"`

	ListenPort uint16 `env:"LISTEN_PORT" envDefault:"8181"`

	Verbosity uint8 `env:"VERBOSE" envDefault:"0"`

	AdultBlockingEnabled     strictBool `env:"ADULT_BLOCKING_ENABLED" envDefault:"1"`
	CategoryFilterEnabled    strictBool `env:"CATEGORY_FILTER_ENABLED" envDefault:"0"`
	CrashOutputEnabled       strictBool `env:"CRASH_OUTPUT_ENABLED" envDefault:"0"`
	CustomDomainsEnabled     strictBool `env:"CUSTOM_DOMAINS_ENABLED" envDefault:"1"`
	LogTimestamp             strictBool `env:"LOG_TIMESTAMP" envDefault:"1"`
	NewRegDomainsEnabled     strictBool `env:"NEW_REG_DOMAINS_ENABLED" envDefault:"1"`
	SafeBrowsingEnabled      strictBool `env:"SAFE_BROWSING_ENABLED" envDefault:"1"`
	BlockedServiceEnabled    strictBool `env:"BLOCKED_SERVICE_ENABLED" envDefault:"1"`
	QueryLogSemaphoreEnabled strictBool `env:"QUERYLOG_SEMAPHORE_ENABLED"`
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
	errs := []error{
		validate.NotNegative("MAX_THREADS", envs.MaxThreads),
	}

	errs = envs.validateHTTPURLs(errs)

	if s := envs.FilterIndexURL.Scheme; !strings.EqualFold(s, urlutil.SchemeFile) &&
		!urlutil.IsValidHTTPURLScheme(s) {
		errs = append(errs, fmt.Errorf(
			"%s: not a valid http(s) url or file uri",
			"FILTER_INDEX_URL",
		))
	}

	err = envs.validateCategoryFilterIndex()
	if err != nil {
		errs = append(errs, fmt.Errorf("CATEGORY_FILTER_INDEX_URL: %w", err))
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

	errs = envs.validateCrashOutput(errs)
	errs = envs.validateCustomDomains(errs)
	errs = envs.validateDNSCheck(errs)
	errs = envs.validateQueryLogSemaphore(errs)
	errs = envs.validateRateLimit(errs)
	errs = envs.validateRateLimitURLs(errs)
	errs = envs.validateSessionTickets(errs)
	errs = envs.validateStandardAccess(errs)

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

// validateCategoryFilterIndex returns an error if the CATEGORY_FILTER_INDEX_URL
// environment variable contains an invalid value.
func (envs *environment) validateCategoryFilterIndex() (err error) {
	if !envs.CategoryFilterEnabled {
		return nil
	}

	if envs.CategoryFilterIndexURL == nil {
		return errors.ErrNoValue
	}

	s := envs.CategoryFilterIndexURL.Scheme
	if !strings.EqualFold(s, urlutil.SchemeFile) && !urlutil.IsValidHTTPURLScheme(s) {
		return errors.Error("not a valid http(s) url or file uri")
	}

	return nil
}

// validateWebStaticDir returns an error if the WEB_STATIC_DIR environment
// variable contains an invalid value.
func (envs *environment) validateWebStaticDir() (err error) {
	if !envs.WebStaticDirEnabled {
		return nil
	}

	dirPath := envs.WebStaticDir
	if dirPath == "" {
		return errors.ErrEmptyValue
	}

	return validateDir(dirPath)
}

// validateDir is a best-effort check to make sure the directory exists.
//
// TODO(a.garipov):  Consider moving to golibs.
func validateDir(dirPath string) (err error) {
	fi, err := os.Stat(dirPath)
	if err != nil {
		return err
	}

	if !fi.IsDir() {
		return errors.Error("not a directory")
	}

	return nil
}

// validateCrashOutput appends validation errors to errs if the environment
// variables for crash reporting contain errors.
func (envs *environment) validateCrashOutput(orig []error) (errs []error) {
	errs = orig

	if !envs.CrashOutputEnabled {
		return errs
	}

	dirPath := envs.WebStaticDir
	if dirPath != "" {
		err := validateDir(dirPath)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return append(errs,
		validate.NotEmpty("CRASH_OUTPUT_DIR", envs.CrashOutputDir),
		validate.NotEmpty("CRASH_OUTPUT_PREFIX", envs.CrashOutputPrefix),
	)
}

// validateCustomDomains appends validation errors to errs if the environment
// variables for custom domains contain errors.
func (envs *environment) validateCustomDomains(errs []error) (res []error) {
	res = errs

	if !envs.CustomDomainsEnabled {
		return res
	}

	res = append(res,
		validate.NotEmpty("env CUSTOM_DOMAINS_CACHE_PATH", envs.CustomDomainsCachePath),
		validate.Positive("env CUSTOM_DOMAINS_REFRESH_INTERVAL", envs.CustomDomainsRefreshIvl),
	)

	if err := validate.NotNil("env CUSTOM_DOMAINS_URL", envs.CustomDomainsURL); err != nil {
		res = append(res, err)
	} else if err = urlutil.ValidateGRPCURL(&envs.CustomDomainsURL.URL); err != nil {
		res = append(res, fmt.Errorf("env CUSTOM_DOMAINS_URL: %w", err))
	}

	return res
}

// validateDNSCheck appends validation errors to errs if the environment
// variables for DNS check contain errors.
func (envs *environment) validateDNSCheck(errs []error) (res []error) {
	res = errs

	ttl := time.Duration(envs.DNSCheckKVTTL)

	var err error
	switch typ := envs.DNSCheckKVType; typ {
	case kvModeBackend:
		res = envs.validateBackendKV(res)
		err = validate.Positive("env DNSCHECK_KV_TTL", ttl)
	case kvModeCache:
		res = envs.validateCache(res)
	case kvModeConsul:
		err = validate.InRange("env DNSCHECK_KV_TTL", ttl, consulkv.MinTTL, consulkv.MaxTTL)
	case kvModeRedis:
		err = validate.NoLessThan("env DNSCHECK_KV_TTL", ttl, rediskv.MinTTL)
	default:
		err = fmt.Errorf("env DNSCHECK_KV_TYPE: %w: %q", errors.ErrBadEnumValue, typ)
	}

	if err != nil {
		res = append(res, err)
	}

	return res
}

// validateDNSCheck appends validation errors to errs if the environment
// variables for rate limit contain errors.
func (envs *environment) validateRateLimit(errs []error) (res []error) {
	switch typ := envs.RateLimitAllowlistType; typ {
	case rlAllowlistTypeBackend, rlAllowlistTypeConsul:
		// Go on.
	default:
		err := fmt.Errorf("env RATELIMIT_ALLOWLIST_TYPE: %w: %q", errors.ErrBadEnumValue, typ)

		return append(errs, err)
	}

	return errs
}

// validateSessionTickets appends validation errors to errs if the environment
// variables for session tickets contain errors.
func (envs *environment) validateSessionTickets(errs []error) (res []error) {
	res = errs

	err := validate.NotEmpty("env SESSION_TICKET_TYPE", envs.SessionTicketType)
	if err != nil {
		return append(res, err)
	}

	err = validate.Positive("env SESSION_TICKET_REFRESH_INTERVAL", envs.SessionTicketRefreshIvl)
	if err != nil {
		return append(res, err)
	}

	switch typ := envs.SessionTicketType; typ {
	case sessionTicketLocal:
		return res
	case sessionTicketRemote:
		res = append(
			res,
			validate.NotEmpty("env SESSION_TICKET_API_KEY", envs.SessionTicketAPIKey),
			validate.NotEmpty("env SESSION_TICKET_CACHE_PATH", envs.SessionTicketCachePath),
			validate.NotEmpty("env SESSION_TICKET_INDEX_NAME", envs.SessionTicketIndexName),
		)

		if err = validate.NotNil("env SESSION_TICKET_URL", envs.SessionTicketURL); err != nil {
			res = append(res, err)
		} else if err = urlutil.ValidateGRPCURL(&envs.SessionTicketURL.URL); err != nil {
			res = append(res, fmt.Errorf("env SESSION_TICKET_URL: %w", err))
		}
	default:
		err = fmt.Errorf("env SESSION_TICKET_TYPE: %w: %q", errors.ErrBadEnumValue, typ)

		return append(res, err)
	}

	return res
}

// validateStandardAccess appends validation errors to the given errs if
// environment variables for standard access contain errors.
func (envs *environment) validateStandardAccess(errs []error) (res []error) {
	res = errs

	switch typ := envs.StandardAccessType; typ {
	case standardAccessOff:
		return res
	case standardAccessBackend:
		res = append(
			res,
			validate.NotEmpty("env STANDARD_ACCESS_API_KEY", envs.StandardAccessAPIKey),
			validate.Positive("env STANDARD_ACCESS_REFRESH_INTERVAL", envs.StandardAccessRefreshIvl),
			validate.Positive("env STANDARD_ACCESS_TIMEOUT", envs.StandardAccessTimeout),
		)

		if err := validate.NotNil("env STANDARD_ACCESS_URL", envs.StandardAccessURL); err != nil {
			res = append(res, err)
		} else if err = urlutil.ValidateGRPCURL(&envs.StandardAccessURL.URL); err != nil {
			res = append(res, fmt.Errorf("env STANDARD_ACCESS_URL: %w", err))
		}
	default:
		err := fmt.Errorf("env STANDARD_ACCESS_TYPE: %w: %q", errors.ErrBadEnumValue, typ)

		return append(res, err)
	}

	return res
}

// validateProfilesConf returns an error if environment variables for profiles
// database configuration contain errors.
func (envs *environment) validateProfilesConf(profilesEnabled bool) (err error) {
	if !profilesEnabled {
		return nil
	}

	var errs []error
	errs = envs.validateProfilesURLs(errs)

	errs = append(
		errs,
		validate.NoGreaterThan("PROFILES_MAX_RESP_SIZE", envs.ProfilesMaxRespSize, math.MaxInt),
		validate.Positive("PROFILES_CACHE_INTERVAL", envs.ProfilesCacheIvl),
	)

	return errors.Join(errs...)
}

// validateCache appends validation errors to orig if environment variables for
// the querylog semaphore contain errors.
func (envs *environment) validateQueryLogSemaphore(orig []error) (errs []error) {
	errs = orig

	if !envs.QueryLogSemaphoreEnabled {
		return errs
	}

	err := validate.Positive("QUERYLOG_SEMAPHORE_LIMIT", envs.QueryLogSemaphoreLimit)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		errs = append(errs, err)
	}

	return errs
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
func (envs *environment) validateRateLimitURLs(errs []error) (withURLs []error) {
	rlURL := envs.BackendRateLimitURL
	rlEnv := "BACKEND_RATELIMIT_URL"
	validateFunc := urlutil.ValidateGRPCURL

	if envs.RateLimitAllowlistType == rlAllowlistTypeConsul {
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
