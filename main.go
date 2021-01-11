package main

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"

	// Plug in CoreDNS plugins that are needed
	_ "github.com/coredns/coredns/plugin/any"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/debug"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/file"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/metrics"
	_ "github.com/coredns/coredns/plugin/pprof"
	_ "github.com/coredns/coredns/plugin/tls"
	_ "github.com/coredns/coredns/plugin/whoami"

	// Our CoreDNS plugins forks
	_ "github.com/AdguardTeam/AdGuardDNS/health"

	// Our plugins
	_ "github.com/AdguardTeam/AdGuardDNS/dnsdb"
	_ "github.com/AdguardTeam/AdGuardDNS/dnsfilter"
	_ "github.com/AdguardTeam/AdGuardDNS/info"
	_ "github.com/AdguardTeam/AdGuardDNS/lrucache"
	_ "github.com/AdguardTeam/AdGuardDNS/ratelimit"
	_ "github.com/AdguardTeam/AdGuardDNS/refuseany"
	_ "github.com/AdguardTeam/AdGuardDNS/upstream"
)

// Directives are registered in the order they should be
// executed.
//
// Ordering is VERY important. Every plugin will
// feel the effects of all other plugin below
// (after) them during a request, but they must not
// care what plugin above them are doing.
var directives = []string{
	"bind",
	"tls",
	"debug",
	"pprof",
	"prometheus",
	"errors",
	"log",
	// Start: our plugins. The order is important
	"info",
	"refuseany",
	"ratelimit",
	"dnsfilter", // It will process cached responses as well
	"dnsdb",     // DNSDB plugin is after the dnsfilter -- to see the real responses
	"lrucache",  // Cache: set it to be the last of our plugins
	// End: our plugins
	"cache",
	"file",
	// Start: our forked CoreDNS plugins
	"health",
	// End: our forked CoreDNS plugins
	"upstream", // upstream - our replacement for "forward" and "alternate"
	"whoami",
	"on",
}

func init() {
	dnsserver.Directives = directives
}

func main() {
	coremain.Run()
}
