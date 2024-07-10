package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/caarlos0/env/v7"
	"github.com/getsentry/sentry-go"
)

// environments represents the configuration that is kept in the environment.
type environments struct {
	AdultBlockingURL         *urlutil.URL `env:"ADULT_BLOCKING_URL,notEmpty"`
	BillStatURL              *urlutil.URL `env:"BILLSTAT_URL,notEmpty"`
	BlockedServiceIndexURL   *urlutil.URL `env:"BLOCKED_SERVICE_INDEX_URL,notEmpty"`
	ConsulAllowlistURL       *urlutil.URL `env:"CONSUL_ALLOWLIST_URL,notEmpty"`
	ConsulDNSCheckKVURL      *urlutil.URL `env:"CONSUL_DNSCHECK_KV_URL"`
	ConsulDNSCheckSessionURL *urlutil.URL `env:"CONSUL_DNSCHECK_SESSION_URL"`
	FilterIndexURL           *urlutil.URL `env:"FILTER_INDEX_URL,notEmpty"`
	GeneralSafeSearchURL     *urlutil.URL `env:"GENERAL_SAFE_SEARCH_URL,notEmpty"`
	LinkedIPTargetURL        *urlutil.URL `env:"LINKED_IP_TARGET_URL"`
	NewRegDomainsURL         *urlutil.URL `env:"NEW_REG_DOMAINS_URL,notEmpty"`
	ProfilesURL              *urlutil.URL `env:"PROFILES_URL,notEmpty"`
	RuleStatURL              *urlutil.URL `env:"RULESTAT_URL"`
	SafeBrowsingURL          *urlutil.URL `env:"SAFE_BROWSING_URL,notEmpty"`
	YoutubeSafeSearchURL     *urlutil.URL `env:"YOUTUBE_SAFE_SEARCH_URL,notEmpty"`

	BillStatAPIKey    string `env:"BILLSTAT_API_KEY"`
	ConfPath          string `env:"CONFIG_PATH" envDefault:"./config.yaml"`
	FilterCachePath   string `env:"FILTER_CACHE_PATH" envDefault:"./filters/"`
	GeoIPASNPath      string `env:"GEOIP_ASN_PATH" envDefault:"./asn.mmdb"`
	GeoIPCountryPath  string `env:"GEOIP_COUNTRY_PATH" envDefault:"./country.mmdb"`
	ProfilesAPIKey    string `env:"PROFILES_API_KEY"`
	ProfilesCachePath string `env:"PROFILES_CACHE_PATH" envDefault:"./profilecache.pb"`
	QueryLogPath      string `env:"QUERYLOG_PATH" envDefault:"./querylog.jsonl"`
	SSLKeyLogFile     string `env:"SSL_KEY_LOG_FILE"`
	SentryDSN         string `env:"SENTRY_DSN" envDefault:"stderr"`

	ListenAddr net.IP `env:"LISTEN_ADDR" envDefault:"127.0.0.1"`

	ListenPort uint16 `env:"LISTEN_PORT" envDefault:"8181"`

	LogTimestamp    strictBool `env:"LOG_TIMESTAMP" envDefault:"1"`
	LogVerbose      strictBool `env:"VERBOSE" envDefault:"0"`
	ProfilesEnabled strictBool `env:"PROFILES_ENABLED" envDefault:"1"`
}

// readEnvs reads the configuration.
func readEnvs() (envs *environments, err error) {
	envs = &environments{}
	err = env.Parse(envs)
	if err != nil {
		return nil, fmt.Errorf("parsing environments: %w", err)
	}

	return envs, nil
}

// configureLogs sets the configuration for the plain text logs.  It also
// returns a [slog.Logger] for code that uses it.
func (envs *environments) configureLogs() (slogLogger *slog.Logger) {
	var flags int
	if envs.LogTimestamp {
		flags = log.LstdFlags | log.Lmicroseconds
	}

	log.SetFlags(flags)

	if envs.LogVerbose {
		log.SetLevel(log.DEBUG)
	}

	return slogutil.New(&slogutil.Config{
		Output:       os.Stdout,
		Format:       slogutil.FormatAdGuardLegacy,
		AddTimestamp: bool(envs.LogTimestamp),
		Verbose:      bool(envs.LogVerbose),
	})
}

// buildErrColl builds and returns an error collector from environment.
func (envs *environments) buildErrColl() (errColl errcoll.Interface, err error) {
	dsn := envs.SentryDSN
	if dsn == "stderr" {
		return errcoll.NewWriterErrorCollector(os.Stderr), nil
	}

	cli, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:              dsn,
		AttachStacktrace: true,
		Release:          agd.Version(),
	})
	if err != nil {
		return nil, err
	}

	return errcoll.NewSentryErrorCollector(cli), nil
}

// geoIP returns an GeoIP database implementation from environment.
func (envs *environments) geoIP(
	ctx context.Context,
	c *geoIPConfig,
	cacheManager agdcache.Manager,
) (g *geoip.File, err error) {
	log.Debug("using geoip files %q and %q", envs.GeoIPASNPath, envs.GeoIPCountryPath)

	g = geoip.NewFile(&geoip.FileConfig{
		CacheManager:   cacheManager,
		ASNPath:        envs.GeoIPASNPath,
		CountryPath:    envs.GeoIPCountryPath,
		HostCacheSize:  c.HostCacheSize,
		IPCacheSize:    c.IPCacheSize,
		AllTopASNs:     geoip.DefaultTopASNs,
		CountryTopASNs: geoip.DefaultCountryTopASNs,
	})

	err = g.Refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating geoip: initial refresh: %w", err)
	}

	return g, nil
}

// debugConf returns a debug HTTP service configuration from environment.
func (envs *environments) debugConf(dnsDB dnsdb.Interface) (conf *debugsvc.Config) {
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
		DNSDBAddr:    dnsDBAddr,
		DNSDBHandler: dnsDBHdlr,

		APIAddr:        addr,
		PprofAddr:      addr,
		PrometheusAddr: addr,
	}

	return conf
}

// buildRuleStat returns a filtering rule statistics collector from environment and
// registers its refresher in sigHdlr, if necessary.
func (envs *environments) buildRuleStat(
	sigHdlr *service.SignalHandler,
	errColl errcoll.Interface,
) (r rulestat.Interface, err error) {
	if envs.RuleStatURL == nil {
		log.Info("main: warning: not collecting rule stats")

		return rulestat.Empty{}, nil
	}

	httpRuleStat := rulestat.NewHTTP(&rulestat.HTTPConfig{
		ErrColl: errColl,
		URL:     &envs.RuleStatURL.URL,
	})

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:   ctxWithDefaultTimeout,
		Refresher: httpRuleStat,
		Name:      "rulestat",
		// TODO(ameshkov): Consider making configurable.
		Interval:          10 * time.Minute,
		RefreshOnShutdown: true,
		RandomizeStart:    false,
	})
	err = refr.Start(context.Background())
	if err != nil {
		return nil, fmt.Errorf("starting rulestat refresher: %w", err)
	}

	sigHdlr.Add(refr)

	return httpRuleStat, nil
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
