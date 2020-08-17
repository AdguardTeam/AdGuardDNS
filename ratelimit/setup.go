package ratelimit

import (
	"sort"
	"strconv"
	"sync"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

//
// helper functions
//
func init() {
	caddy.RegisterPlugin("ratelimit", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

type plug struct {
	Next plugin.Handler

	// configuration for creating above
	ratelimit int // in requests per second per IP

	// if the IP gets blocked more times than the specified backOffTTL
	// it will stay blocked until this period ends
	backOffLimit int

	// whitelist is a list of whitelisted IP addresses
	// IMPORTANT: must be sorted
	whitelist []string

	// consulURL - URL of the consul service where we can get a list
	// of services to add to the whitelist
	consulURL string

	// consulTTL - ttl of the consul list. The plugin will attempt
	// to reload this list every "consulTTL" seconds.
	consulTTL int

	// consulWhitelist -- whitelist loaded from the consul web service
	// IMPORTANT: must be sorted
	consulWhitelist      []string
	consulWhitelistGuard sync.Mutex
}

// Name returns name of the plugin as seen in Corefile and plugin.cfg
func (p *plug) Name() string { return "ratelimit" }

func setupPlugin(c *caddy.Controller) (*plug, error) {
	p := &plug{
		ratelimit:    defaultRatelimit,
		backOffLimit: defaultBackOffLimit,
	}

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) > 0 {
			ratelimit, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, c.ArgErr()
			}
			p.ratelimit = ratelimit
		}
		if len(args) > 1 {
			backOffLimit, err := strconv.Atoi(args[1])
			if err != nil {
				return nil, c.ArgErr()
			}
			p.backOffLimit = backOffLimit
		}
		for c.NextBlock() {
			switch c.Val() {
			case "whitelist":
				p.whitelist = c.RemainingArgs()

				if len(p.whitelist) > 0 {
					sort.Strings(p.whitelist)
				}
			case "consul":
				args = c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.ArgErr()
				}

				p.consulURL = args[0]
				consulTTL, err := strconv.Atoi(args[1])
				if err != nil || consulTTL <= 0 {
					return nil, c.ArgErr()
				}
				p.consulTTL = consulTTL
			}
		}
	}

	return p, nil
}

func setup(c *caddy.Controller) error {
	clog.Infof("Initializing the ratelimit plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	p, err := setupPlugin(c)
	if err != nil {
		return err
	}

	if p.consulURL != "" {
		err = p.reloadConsulWhitelist()
		if err != nil {
			return err
		}

		// Start the periodic reload job
		go p.periodicConsulWhitelistReload()
	}

	config := dnsserver.GetConfig(c)
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	c.OnStartup(func() error {
		metrics.MustRegister(c, RateLimitedCounter, BackOffCounter, RateLimitersCountGauge,
			RateLimitedIPAddressesCountGauge, WhitelistedCounter, WhitelistCountGauge)
		return nil
	})

	clog.Infof("Finished initializing the ratelimit plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	return nil
}
