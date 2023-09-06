// Package dnssvctest contains common constants and utilities for the internal
// DNS-service packages.
package dnssvctest

import (
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// Timeout is the common timeout for tests.
const Timeout time.Duration = 1 * time.Second

// String representations of the common IDs for tests.
const (
	DeviceIDStr  = "dev1234"
	ProfileIDStr = "prof1234"
)

// DeviceID is the common device ID for tests.
const DeviceID agd.DeviceID = DeviceIDStr

// ProfileID is the common profile ID for tests.
const ProfileID agd.ProfileID = ProfileIDStr

// Common addresses for tests.
var (
	ClientIP   = net.IP{1, 2, 3, 4}
	RemoteAddr = &net.TCPAddr{
		IP:   ClientIP,
		Port: 12345,
	}

	ClientAddrPort = RemoteAddr.AddrPort()
	ClientAddr     = ClientAddrPort.Addr()

	ServerAddr = netip.MustParseAddr("5.6.7.8")
	LocalAddr  = &net.TCPAddr{
		IP:   ServerAddr.AsSlice(),
		Port: 54321,
	}
)
