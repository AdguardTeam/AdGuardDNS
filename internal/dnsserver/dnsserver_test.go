package dnsserver_test

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/timeutil"
)

// testTimeout is a common timeout for tests.
const testTimeout = dnsserver.DefaultReadTimeout

// testClock is a common clock for tests.
var testClock = timeutil.SystemClock{}
