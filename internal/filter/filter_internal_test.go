package filter

import (
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
)

// Common test constants.

// testTimeout is the timeout for tests.
const testTimeout = 1 * time.Second

// testProfID is the profile ID for tests.
const testProfID agd.ProfileID = "prof1234"

// testReqHost is the request host for tests.
const testReqHost = "www.example.com"

// testReqFQDN is the request FQDN for tests.
const testReqFQDN = testReqHost + "."

// testRemoteIP is the client IP for tests
var testRemoteIP = netip.MustParseAddr("1.2.3.4")

// newConstructor returns a standard dnsmsg.Constructor for tests.
//
// TODO(a.garipov): Use [agdtest.NewConstructor] once the package is split and
// import cycles are resolved.
func newConstructor() (c *dnsmsg.Constructor) {
	return dnsmsg.NewConstructor(&dnsmsg.BlockingModeNullIP{}, 10*time.Second)
}
