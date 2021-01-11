package lrucache

import (
	"strconv"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

// serverBlockCaches stores a map of caches and server blocks.
// The idea is to have one cache per server block, and not per listen address
// as it works by default.
var serverBlockCaches = make(map[int]*cache)

// plug represents the CoreDNS plugin and contains
// a link to the next plugin in the chain.
type plug struct {
	Next  plugin.Handler
	cache *cache
}

// Name returns name of the plugin as seen in Corefile and plugin.cfg
func (p *plug) Name() string { return "lrucache" }

func init() {
	caddy.RegisterPlugin("lrucache", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setupPlugin(c *caddy.Controller) (*plug, error) {
	p := &plug{
		cache: &cache{},
	}

	if serverBlockCache, ok := serverBlockCaches[c.ServerBlockIndex]; ok {
		clog.Infof("Cache was already initialized for server block %d", c.ServerBlockIndex)
		p.cache = serverBlockCache
		return p, nil
	}

	var serverBlockCache = &cache{}

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) > 0 {
			size, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, c.ArgErr()
			}
			clog.Infof("Cache size is %d", size)
			serverBlockCache.cacheSize = size
		}
	}

	clog.Infof("Initialized cache for server block %d", c.ServerBlockIndex)
	serverBlockCaches[c.ServerBlockIndex] = serverBlockCache
	p.cache = serverBlockCache
	return p, nil
}

func setup(c *caddy.Controller) error {
	clog.Infof("Initializing the lrucache plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	p, err := setupPlugin(c)
	if err != nil {
		return err
	}

	config := dnsserver.GetConfig(c)

	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	clog.Infof("Finished initializing the lrucache plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	return nil
}
