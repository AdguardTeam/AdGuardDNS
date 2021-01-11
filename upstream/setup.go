package upstream

import (
	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

func init() { plugin.Register("upstream", setup) }

func setup(c *caddy.Controller) error {
	clog.Infof("Initializing the upstream plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	p, err := setupPlugin(c)
	if err != nil {
		return err
	}

	config := dnsserver.GetConfig(c)
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		return p
	})

	clog.Infof("Finished initializing the upstream plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	return nil
}

// setupPlugin parses and validates the plugin configuration
func setupPlugin(c *caddy.Controller) (*Upstream, error) {
	u := &Upstream{}

	if !c.Next() {
		return nil, c.ArgErr()
	}

	// Parse the upstream IP address
	args := c.RemainingArgs()
	if len(args) != 1 {
		return nil, c.ArgErr()
	}
	addr := args[0]
	if len(addr) == 0 {
		return nil, c.ArgErr()
	}

	p, err := NewProxy(addr)
	if err != nil {
		return nil, err
	}
	u.main = p

	for c.NextBlock() {
		switch c.Val() {
		case "fallback":
			addrs := c.RemainingArgs()
			if len(addrs) == 0 {
				return nil, c.ArgErr()
			}
			for _, addr := range addrs {
				p, err := NewProxy(addr)
				if err != nil {
					return nil, err
				}
				u.fallbacks = append(u.fallbacks, p)
			}
		}
	}

	return u, nil
}
