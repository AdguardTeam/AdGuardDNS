package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// DNS upstream configuration

// upstreamConfig module configuration
type upstreamConfig struct {
	// Healthcheck contains the upstream healthcheck configuration.
	Healthcheck *upstreamHealthcheckConfig `yaml:"healthcheck"`

	// Server is the upstream url of the server we're using to forward DNS
	// queries. It starts with tcp://, udp://, or with an IP address.
	Server string `yaml:"server"`

	// FallbackServers is a list of the DNS servers we're using to fallback to
	// when the upstream server fails to respond
	FallbackServers []netip.AddrPort `yaml:"fallback"`

	// Timeout is the timeout for DNS requests to the upstreams.
	Timeout timeutil.Duration `yaml:"timeout"`
}

// toInternal converts c to the data storage configuration for the DNS server.
func (c *upstreamConfig) toInternal() (conf *agd.Upstream, err error) {
	net, addrPort, err := splitUpstreamURL(c.Server)
	if err != nil {
		return nil, err
	}

	return &agd.Upstream{
		Server:          addrPort,
		Network:         net,
		FallbackServers: c.FallbackServers,
		Timeout:         c.Timeout.Duration,
	}, nil
}

// validate returns an error if the upstream configuration is invalid.
func (c *upstreamConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.Server == "":
		return errors.Error("no server")
	case len(c.FallbackServers) == 0:
		return errors.Error("no fallback")
	case c.Timeout.Duration <= 0:
		return newMustBePositiveError("timeout", c.Timeout)
	}

	err = validateAddrs(c.FallbackServers)
	if err != nil {
		return fmt.Errorf("fallback: %w", err)
	}

	return errors.Annotate(c.Healthcheck.validate(), "healthcheck: %w")
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
	errColl agd.ErrorCollector,
) (refr agd.Service) {
	if !conf.Healthcheck.Enabled {
		return agd.EmptyService{}
	}

	return agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
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
	})
}
