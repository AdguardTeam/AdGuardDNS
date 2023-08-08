package dnssvc

import (
	"net"
	"net/netip"
)

// Common addresses for tests.
var (
	testClientIP = net.IP{1, 2, 3, 4}
	testRAddr    = &net.TCPAddr{
		IP:   testClientIP,
		Port: 12345,
	}

	testClientAddrPort = testRAddr.AddrPort()
	testClientAddr     = testClientAddrPort.Addr()

	testServerAddr = netip.MustParseAddr("5.6.7.8")
	testLocalAddr  = &net.TCPAddr{
		IP:   testServerAddr.AsSlice(),
		Port: 54321,
	}
)

// testDeviceID is the common device ID for tests
const testDeviceID = "dev1234"

// testProfileID is the common profile ID for tests
const testProfileID = "prof1234"
