package dnsdb

import (
	"fmt"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

const bufferRotationPeriod = 15 * time.Minute

var (
	// Keeping one dnsDB instance per address
	dnsDBMap = map[string]*dnsDB{}
)

func init() {
	caddy.RegisterPlugin("dnsdb", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	clog.Infof("Initializing the dnsdb plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	p, err := parse(c)
	if err != nil {
		return err
	}

	config := dnsserver.GetConfig(c)
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	c.OnStartup(func() error {
		metrics.MustRegister(c, dbSizeGauge, dbRotateTimestamp, bufferSizeGauge, elapsedDBSave)
		return nil
	})

	clog.Infof("Finished initializing the dnsfilter plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	return nil
}

func parse(c *caddy.Controller) (*plug, error) {
	p := &plug{}

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 1 {
			p.path = args[0]
		}

		if len(args) == 2 {
			p.addr = args[0]
			p.path = args[1]
		}

		if len(args) == 0 || len(args) > 2 {
			return nil, fmt.Errorf("cannot initialize DNSDB plugin - invalid args: %v", args)
		}
	}

	if db, ok := dnsDBMap[p.addr]; ok {
		if db.path != p.path {
			return nil, fmt.Errorf("dnsdb with a different path already listens to %s", p.addr)
		}
	} else {
		// Init the new dnsDB
		d, err := newDB(p.path)
		if err != nil {
			return nil, err
		}
		dnsDBMap[p.addr] = d

		// Start the listener
		err = startListener(p.addr, d)
		if err != nil {
			return nil, err
		}

		ticker := time.NewTicker(bufferRotationPeriod)
		go func() {
			time.Sleep(bufferRotationPeriod)
			for t := range ticker.C {
				_ = t // we don't print the ticker time, so assign this `t` variable to underscore `_` to avoid error
				d.Save()
			}
		}()
	}

	return p, nil
}
