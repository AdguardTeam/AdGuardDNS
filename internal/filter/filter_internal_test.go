package filter

import (
	"net/netip"
	"time"
)

// testTimeout is the timeout for common test operations.
const testTimeout = 1 * time.Second

// testRemoteIP is the client IP for tests
var testRemoteIP = netip.MustParseAddr("1.2.3.4")
