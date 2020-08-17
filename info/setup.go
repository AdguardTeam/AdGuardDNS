package info

import (
	"errors"
	"fmt"
	"net"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

func init() {
	caddy.RegisterPlugin("info", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	clog.Infof("Initializing the info plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	p, err := setupPlugin(c)
	if err != nil {
		return err
	}

	config := dnsserver.GetConfig(c)
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	clog.Infof("Finished initializing the info plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	return nil
}

// setupPlugin parses and validates the plugin configuration
func setupPlugin(c *caddy.Controller) (*info, error) {
	i := &info{}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "domain":
				if !c.NextArg() || len(c.Val()) == 0 {
					return nil, c.ArgErr()
				}
				i.domain = c.Val()
			case "type":
				if !c.NextArg() || len(c.Val()) == 0 {
					return nil, c.ArgErr()
				}
				i.serverType = c.Val()
			case "protocol":
				if !c.NextArg() || len(c.Val()) == 0 {
					return nil, c.ArgErr()
				}
				i.protocol = c.Val()
			case "canary":
				if !c.NextArg() || len(c.Val()) == 0 {
					return nil, c.ArgErr()
				}
				i.canary = c.Val()
			case "addr":
				args := c.RemainingArgs()
				for _, arg := range args {
					ip := net.ParseIP(arg)
					if ip == nil {
						return nil, fmt.Errorf("invalid IP %s", arg)
					}

					if ip.To4() == nil {
						i.addrs6 = append(i.addrs6, ip)
					} else {
						i.addrs4 = append(i.addrs4, ip)
					}
				}
			}
		}
	}

	return validate(i)
}

func validate(i *info) (*info, error) {
	if i.domain == "" {
		return nil, errors.New("domain must be set")
	}

	if i.serverType == "" {
		return nil, errors.New("server type must be set")
	}

	if i.protocol != "auto" &&
		i.protocol != "dns" &&
		i.protocol != "doh" &&
		i.protocol != "dot" &&
		i.protocol != "dnscrypt" {
		return nil, fmt.Errorf("invalid protocol %s", i.protocol)
	}

	if len(i.addrs4) == 0 && len(i.addrs6) == 0 {
		return nil, errors.New("addr must be set")
	}

	return i, nil
}
