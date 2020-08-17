package refuseany

import (
	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

func init() {
	caddy.RegisterPlugin("refuseany", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

type plug struct {
	Next plugin.Handler
}

// Name returns name of the plugin as seen in Corefile and plugin.cfg
func (p *plug) Name() string { return "refuseany" }

func setup(c *caddy.Controller) error {
	clog.Infof("Initializing the refuseany plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])

	p := &plug{}
	config := dnsserver.GetConfig(c)

	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	c.OnStartup(func() error {
		metrics.MustRegister(c, refusedAnyTotal)
		return nil
	})

	clog.Infof("Finished initializing the refuseany plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	return nil
}
