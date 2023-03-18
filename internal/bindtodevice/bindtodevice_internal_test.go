package bindtodevice

import (
	"net"
	"time"
)

// Common addresses for tests.
var (
	testLAddr = &net.UDPAddr{
		IP:   net.IP{1, 2, 3, 4},
		Port: 53,
	}
	testRAddr = &net.UDPAddr{
		IP:   net.IP{5, 6, 7, 8},
		Port: 1234,
	}
)

// Common timeout for tests
const testTimeout = 1 * time.Second
