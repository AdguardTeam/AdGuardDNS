package cmd

import (
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	dnssvcprom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/contextutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
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

// toInternal converts c to the upstream configuration for the DNS server.  c
// must be valid.
func (c *upstreamConfig) toInternal(
	logger *slog.Logger,
	mtrcListener *dnssvcprom.ForwardMetricsListener,
) (fwdConf *forward.HandlerConfig) {
	return &forward.HandlerConfig{
		Logger:             logger.With(slogutil.KeyPrefix, "forward"),
		MetricsListener:    mtrcListener,
		Healthcheck:        c.Healthcheck.toInternal(),
		UpstreamsAddresses: toUpstreamConfigs(c.Servers),
		FallbackAddresses:  toUpstreamConfigs(c.Fallback.Servers),
	}
}

// type check
var _ validate.Interface = (*upstreamConfig)(nil)

// Validate implements the [validate.Interface] interface for *upstreamConfig.
func (c *upstreamConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.NotEmptySlice("servers", c.Servers),
	}

	errs = validate.AppendSlice(errs, "servers", c.Servers)

	errs = validate.Append(errs, "fallback", c.Fallback)
	errs = validate.Append(errs, "healthcheck", c.Healthcheck)

	return errors.Join(errs...)
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

		upsNet, err = forward.NewNetwork(u.Scheme)
		if err != nil {
			return upsNet, addrPort, fmt.Errorf("bad server protocol: %w", err)
		}

		addr = u.Host
	}

	if addrPort, err = netip.ParseAddrPort(addr); err != nil {
		return upsNet, addrPort, fmt.Errorf("bad server address %q: %w", addr, err)
	}

	return upsNet, addrPort, nil
}

// upstreamHealthcheckConfig is the configuration for the upstream healthcheck
// feature.
type upstreamHealthcheckConfig struct {
	// DomainTemplate is the interval of upstream healthcheck probes.
	DomainTemplate string `yaml:"domain_template"`

	// NetworkOverride is the network type used for healthcheck queries.  If not
	// empty, it overrides the upstream's own network type for healthcheck
	// queries.
	NetworkOverride string `yaml:"network_override"`

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
var _ validate.Interface = (*upstreamHealthcheckConfig)(nil)

// Validate implements the [validate.Interface] interface for
// *upstreamHealthcheckConfig.
func (c *upstreamHealthcheckConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	} else if !c.Enabled {
		return nil
	}

	var netErr error
	if c.NetworkOverride != "" {
		_, netErr = forward.NewNetwork(c.NetworkOverride)
	}

	return errors.Join(
		errors.Annotate(netErr, "network_override: %w"),
		validate.NotEmpty("domain_template", c.DomainTemplate),
		validate.Positive("backoff_duration", c.BackoffDuration),
		validate.Positive("interval", c.Interval),
		validate.Positive("timeout", c.Timeout),
	)
}

// toInternal converts c to the upstream healthcheck configuration for the DNS
// server.  c must be valid.
func (c *upstreamHealthcheckConfig) toInternal() (hc *forward.HealthcheckConfig) {
	if !c.Enabled {
		return &forward.HealthcheckConfig{
			Enabled: false,
		}
	}

	return &forward.HealthcheckConfig{
		Enabled:         true,
		DomainTempalate: c.DomainTemplate,
		BackoffDuration: time.Duration(c.BackoffDuration),
		InitDuration:    time.Duration(c.Timeout),
		// Should've been validated in [upstreamHealthcheckConfig.Validate].
		NetworkOverride: errors.Must(forward.NewNetwork(c.NetworkOverride)),
	}
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

	return service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(time.Duration(conf.Healthcheck.Timeout)),
		ErrorHandler:       errcoll.NewRefreshErrorHandler(refrLogger, errColl),
		Refresher:          handler,
		Schedule:           timeutil.NewConstSchedule(time.Duration(conf.Healthcheck.Interval)),
		RefreshOnShutdown:  false,
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
var _ validate.Interface = (*upstreamFallbackConfig)(nil)

// Validate implements the [validate.Interface] interface for
// *upstreamFallbackConfig.
func (c *upstreamFallbackConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.NotEmptySlice("servers", c.Servers),
	}

	errs = validate.AppendSlice(errs, "servers", c.Servers)

	return errors.Join(errs...)
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
var _ validate.Interface = (*upstreamServerConfig)(nil)

// Validate implements the [validate.Interface] interface for
// *upstreamServerConfig.
func (c *upstreamServerConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.Positive("timeout", c.Timeout),
	}

	_, _, err = splitUpstreamURL(c.Address)
	if err != nil {
		errs = append(errs, fmt.Errorf("address: %w", err))
	}

	return errors.Join(errs...)
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
			Timeout: time.Duration(c.Timeout),
		})
	}

	return upsConfs
}
