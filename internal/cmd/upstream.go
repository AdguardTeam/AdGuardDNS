package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// DNS upstream configuration

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
// c is assumed to be valid.
func (c *upstreamConfig) toInternal() (fwdConf *forward.HandlerConfig) {
	upstreams := c.Servers
	fallbacks := c.Fallback.Servers

	upsConfs := toUpstreamConfigs(upstreams)
	fallbackConfs := toUpstreamConfigs(fallbacks)

	metricsListener := prometheus.NewForwardMetricsListener(len(upstreams) + len(fallbacks))

	var hcInit time.Duration
	if c.Healthcheck.Enabled {
		hcInit = c.Healthcheck.Timeout.Duration
	}

	fwdConf = &forward.HandlerConfig{
		MetricsListener:            metricsListener,
		HealthcheckDomainTmpl:      c.Healthcheck.DomainTmpl,
		UpstreamsAddresses:         upsConfs,
		FallbackAddresses:          fallbackConfs,
		HealthcheckBackoffDuration: c.Healthcheck.BackoffDuration.Duration,
		HealthcheckInitDuration:    hcInit,
	}

	return fwdConf
}

// validate returns an error if the upstream configuration is invalid.
func (c *upstreamConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case len(c.Servers) == 0:
		return errors.Error("no servers")
	}

	for i, s := range c.Servers {
		if err = s.validate(); err != nil {
			return fmt.Errorf("servers: at index %d: %w", i, err)
		}
	}

	return coalesceError(
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

// validate returns an error if the upstream healthcheck configuration is
// invalid.
func (c *upstreamHealthcheckConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case !c.Enabled:
		return nil
	case c.DomainTmpl == "":
		return errors.Error("no domain_tmpl")
	case c.Interval.Duration <= 0:
		return newMustBePositiveError("interval", c.Interval)
	case c.Timeout.Duration <= 0:
		return newMustBePositiveError("timeout", c.Timeout)
	case c.BackoffDuration.Duration <= 0:
		return newMustBePositiveError("backoff_duration", c.BackoffDuration)
	}

	return nil
}

// newUpstreamHealthcheck returns refresher worker service that performs
// upstream healthchecks.  conf is assumed to be valid.
func newUpstreamHealthcheck(
	handler *forward.Handler,
	conf *upstreamConfig,
	errColl errcoll.Interface,
) (refr agdservice.Interface) {
	if !conf.Healthcheck.Enabled {
		return agdservice.Empty{}
	}

	return agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(
				context.Background(),
				conf.Healthcheck.Timeout.Duration,
			)
		},
		Refresher:           handler,
		ErrColl:             errColl,
		Name:                "upstream healthcheck",
		Interval:            conf.Healthcheck.Interval.Duration,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: true,
		RandomizeStart:      false,
	})
}

// upstreamFallbackConfig is the configuration for the upstream fallback
// servers.
type upstreamFallbackConfig struct {
	// Servers is a list of the upstream servers configurations we use to
	// fallback when the upstream servers fail to respond.
	Servers []*upstreamServerConfig `yaml:"servers"`
}

// validate returns an error if the upstream fallback configuration is invalid.
func (c *upstreamFallbackConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case len(c.Servers) == 0:
		return errors.Error("no servers")
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

// validate returns an error if the upstream server configuration is invalid.
func (c *upstreamServerConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.Timeout.Duration <= 0:
		return newMustBePositiveError("timeout", c.Timeout)
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
