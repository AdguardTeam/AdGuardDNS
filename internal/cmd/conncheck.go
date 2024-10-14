package cmd

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
)

// connCheckConfig is the connectivity check configuration.
type connCheckConfig struct {
	// ProbeIPv4 is a probe v4 address to perform a check to.
	ProbeIPv4 netip.AddrPort `yaml:"probe_ipv4"`

	// ProbeIPv6 is a probe v6 address to perform a check to.
	ProbeIPv6 netip.AddrPort `yaml:"probe_ipv6"`
}

// type check
var _ validator = (*connCheckConfig)(nil)

// validate implements the [validator] interface for *connCheckConfig.
func (c *connCheckConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.ProbeIPv4 == netip.AddrPort{}:
		return fmt.Errorf("probe_ipv4: %w", errors.ErrEmptyValue)
	}

	return nil
}

// connectivityCheck performs connectivity checks for bind addresses with
// provided dialer and probe addresses.  For each server group it reviews each
// server bind addresses looking up for IPv6 addresses.  If an IPv6 address is
// found, then additionally to a general probe to IPv4 it will perform a check
// to IPv6 probe address.
func connectivityCheck(srvGrps []*agd.ServerGroup, connCheck *connCheckConfig) (err error) {
	probeIPv4 := net.TCPAddrFromAddrPort(connCheck.ProbeIPv4)

	// General check to IPv4 probe address.
	conn4, err := net.DialTCP("tcp4", nil, probeIPv4)
	if err != nil {
		return fmt.Errorf("connectivity check: ipv4: %w", err)
	}

	defer func() {
		errClose := errors.Annotate(conn4.Close(), "connectivity check: closing ipv4: %w")
		err = errors.WithDeferred(err, errClose)
	}()

	if !requireIPv6ConnCheck(srvGrps) {
		return nil
	}

	if (connCheck.ProbeIPv6 == netip.AddrPort{}) {
		return errors.Error("connectivity check: no ipv6 probe address in config")
	}

	probeIPv6 := net.TCPAddrFromAddrPort(connCheck.ProbeIPv6)

	// Check to IPv6 probe address.
	conn6, err := net.DialTCP("tcp6", nil, probeIPv6)
	if err != nil {
		return fmt.Errorf("connectivity check: ipv6: %w", err)
	}

	defer func() {
		errClose := errors.Annotate(conn6.Close(), "connectivity check: closing ipv6: %w")
		err = errors.WithDeferred(err, errClose)
	}()

	return nil
}

// requireIPv6ConnCheck returns true if provided serverGroups require IPv6
// connectivity check.
func requireIPv6ConnCheck(serverGroups []*agd.ServerGroup) (ok bool) {
	for _, srvGrp := range serverGroups {
		for _, s := range srvGrp.Servers {
			if s.HasIPv6() {
				return true
			}
		}
	}

	return false
}
