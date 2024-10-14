package cmd

import (
	"cmp"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/timeutil"
)

// upstreamConfig is the upstream module configuration.
type upstreamConfig struct {
	// Healthcheck contains the upstream healthcheck configuration.
	Healthcheck *upstreamHealthcheckConfig `yaml:"healthcheck"`

	// Fallback is the configuration for the upstream fallback servers.
	Fallback *upstreamFallbackConfig `yaml:"fallback"`

	// Servers is a list of the upstream servers configurations we use to
	// forward DNS queries.
	Servers []*upstreamServerConfig `yaml:"servers"`
}

// toInternal converts c to the data storage configuration for the DNS server.
// c must be valid.
func (c *upstreamConfig) toInternal(logger *slog.Logger) (fwdConf *forward.HandlerConfig) {
	upstreams := c.Servers
	fallbacks := c.Fallback.Servers

	upsConfs := toUpstreamConfigs(upstreams)
	fallbackConfs := toUpstreamConfigs(fallbacks)
	metricsListener := prometheus.NewForwardMetricsListener(metrics.Namespace(), len(upstreams)+len(fallbacks))

	var hcInit time.Duration
	if c.Healthcheck.Enabled {
		hcInit = c.Healthcheck.Timeout.Duration
	}

	fwdConf = &forward.HandlerConfig{
		Logger:                     logger.With(slogutil.KeyPrefix, "forward"),
		MetricsListener:            metricsListener,
		HealthcheckDomainTmpl:      c.Healthcheck.DomainTmpl,
		UpstreamsAddresses:         upsConfs,
		FallbackAddresses:          fallbackConfs,
		HealthcheckBackoffDuration: c.Healthcheck.BackoffDuration.Duration,
		HealthcheckInitDuration:    hcInit,
	}

	return fwdConf
}

// type check
var _ validator = (*upstreamConfig)(nil)

// validate implements the [validator] interface for *upstreamConfig.
func (c *upstreamConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case len(c.Servers) == 0:
		return fmt.Errorf("servers: %w", errors.ErrEmptyValue)
	}

	for i, s := range c.Servers {
		if err = s.validate(); err != nil {
			return fmt.Errorf("servers: at index %d: %w", i, err)
		}
	}

	return cmp.Or(
		validateProp("fallback", c.Fallback.validate),
		validateProp("healthcheck", c.Healthcheck.validate),
	)
}

// splitUpstreamURL separates server url to net protocol and port address.
func splitUpstreamURL(raw string) (upsNet forward.Network, addrPort netip.AddrPort, err error) {
	addr := raw
	upsNet = forward.NetworkAny

	if strings.Contains(raw, "://") {
		var u *url.URL
		u, err = url.Parse(raw)
		if err != nil {
			return upsNet, addrPort, fmt.Errorf("bad server url: %q: %w", raw, err)
		}

		addr = u.Host
		upsNet = forward.Network(u.Scheme)

		switch upsNet {
		case forward.NetworkTCP, forward.NetworkUDP:
			// Go on.
			break
		default:
			return upsNet, addrPort, fmt.Errorf("bad server protocol: %q", u.Scheme)
		}
	}

	if addrPort, err = netip.ParseAddrPort(addr); err != nil {
		return upsNet, addrPort, fmt.Errorf("bad server address: %q", addr)
	}

	return upsNet, addrPort, nil
}

// upstreamHealthcheckConfig is the configuration for the upstream healthcheck
// feature.
type upstreamHealthcheckConfig struct {
	// DomainTmpl is the interval of upstream healthcheck probes.
	DomainTmpl string `yaml:"domain_template"`

	// Interval is the interval of upstream healthcheck probes.
	Interval timeutil.Duration `yaml:"interval"`

	// Timeout is the healthcheck query timeout.
	Timeout timeutil.Duration `yaml:"timeout"`

	// BackoffDuration is the healthcheck query backoff interval.  If the main
	// upstream is down, AdGuardDNS will not return back to the upstream until
	// this time has passed.  The healthcheck is still performed, and each
	// failed check advances the backoff.
	BackoffDuration timeutil.Duration `yaml:"backoff_duration"`

	// Enabled shows if upstream healthcheck is enabled.
	Enabled bool `yaml:"enabled"`
}

// type check
var _ validator = (*upstreamHealthcheckConfig)(nil)

// validate implements the [validator] interface for *upstreamHealthcheckConfig.
func (c *upstreamHealthcheckConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case !c.Enabled:
		return nil
	case c.DomainTmpl == "":
		return fmt.Errorf("domain_template: %w", errors.ErrEmptyValue)
	case c.Interval.Duration <= 0:
		return newNotPositiveError("interval", c.Interval)
	case c.Timeout.Duration <= 0:
		return newNotPositiveError("timeout", c.Timeout)
	case c.BackoffDuration.Duration <= 0:
		return newNotPositiveError("backoff_duration", c.BackoffDuration)
	}

	return nil
}

// newUpstreamHealthcheck returns refresher worker service that performs
// upstream healthchecks.  conf must be valid.
func newUpstreamHealthcheck(
	logger *slog.Logger,
	handler *forward.Handler,
	conf *upstreamConfig,
	errColl errcoll.Interface,
) (refr service.Interface) {
	if !conf.Healthcheck.Enabled {
		return service.Empty{}
	}

	const prefix = "upstream_healthcheck_refresh"
	refrLogger := logger.With(slogutil.KeyPrefix, prefix)
	return agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:           newCtxWithTimeoutCons(conf.Healthcheck.Timeout.Duration),
		Refresher:         agdservice.NewRefresherWithErrColl(handler, refrLogger, errColl, prefix),
		Logger:            refrLogger,
		Interval:          conf.Healthcheck.Interval.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
}

// upstreamFallbackConfig is the configuration for the upstream fallback
// servers.
type upstreamFallbackConfig struct {
	// Servers is a list of the upstream servers configurations we use to
	// fallback when the upstream servers fail to respond.
	Servers []*upstreamServerConfig `yaml:"servers"`
}

// type check
var _ validator = (*upstreamFallbackConfig)(nil)

// validate implements the [validator] interface for *upstreamFallbackConfig.
func (c *upstreamFallbackConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case len(c.Servers) == 0:
		return fmt.Errorf("servers: %w", errors.ErrEmptyValue)
	}

	for i, s := range c.Servers {
		if err = s.validate(); err != nil {
			return fmt.Errorf("servers: at index %d: %w", i, err)
		}
	}

	return nil
}

// upstreamServerConfig is the configuration for the upstream server.
type upstreamServerConfig struct {
	// Address is the url of the DNS server in the `[scheme://]ip:port`
	// format.
	Address string `yaml:"address"`

	// Timeout is the timeout for DNS requests.
	Timeout timeutil.Duration `yaml:"timeout"`
}

// type check
var _ validator = (*upstreamServerConfig)(nil)

// validate implements the [validator] interface for *upstreamServerConfig.
func (c *upstreamServerConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.Timeout.Duration <= 0:
		return newNotPositiveError("timeout", c.Timeout)
	}

	_, _, err = splitUpstreamURL(c.Address)
	if err != nil {
		return fmt.Errorf("invalid addr: %s", c.Address)
	}

	return nil
}

// toUpstreamConfigs converts confs to the list of upstream configurations.
// confs must be valid.
func toUpstreamConfigs(confs []*upstreamServerConfig) (upsConfs []*forward.UpstreamPlainConfig) {
	upsConfs = make([]*forward.UpstreamPlainConfig, 0, len(confs))
	for _, c := range confs {
		net, addrPort, _ := splitUpstreamURL(c.Address)

		upsConfs = append(upsConfs, &forward.UpstreamPlainConfig{
			Network: net,
			Address: addrPort,
			Timeout: c.Timeout.Duration,
		})
	}

	return upsConfs
}
