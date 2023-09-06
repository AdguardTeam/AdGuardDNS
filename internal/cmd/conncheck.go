package cmd

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// Connectivity check configuration

// connCheckConfig is the connectivity check configuration.
type connCheckConfig struct {
	// ProbeIPv4 is a probe v4 address to perform a check to.
	ProbeIPv4 netip.AddrPort `yaml:"probe_ipv4"`

	// ProbeIPv6 is a probe v6 address to perform a check to.
	ProbeIPv6 netip.AddrPort `yaml:"probe_ipv6"`
}

// validate returns an error if the connectivityCheck configuration is invalid.
func (c *connCheckConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.ProbeIPv4 == netip.AddrPort{}:
		return errors.Error("no ipv4")
	}

	return nil
}

// connectivityCheck performs connectivity checks for bind addresses with
// provided dialer and probe addresses.  For each server group it reviews each
// server bind addresses looking up for IPv6 addresses.  If an IPv6 address is
// found, then additionally to a general probe to IPv4 it will perform a check
// to IPv6 probe address.
func connectivityCheck(c *dnssvc.Config, connCheck *connCheckConfig) (err error) {
	probeIPv4 := net.TCPAddrFromAddrPort(connCheck.ProbeIPv4)

	// General check to IPv4 probe address.
	conn, err := net.DialTCP("tcp4", nil, probeIPv4)
	if err != nil {
		return fmt.Errorf("connectivity check: ipv4: %w", err)
	}

	defer func() {
		closeErr := conn.Close()
		if closeErr != nil {
			log.Fatalf("connectivity check: ipv4: %v", closeErr)
		}
	}()

	if !requireIPv6ConnCheck(c.ServerGroups) {
		return nil
	}

	if (connCheck.ProbeIPv6 == netip.AddrPort{}) {
		log.Fatal("connectivity check: no ipv6 probe address in config")
	}

	probeIPv6 := net.TCPAddrFromAddrPort(connCheck.ProbeIPv6)

	// Check to IPv6 probe address.
	connV6, err := net.DialTCP("tcp6", nil, probeIPv6)
	if err != nil {
		return fmt.Errorf("connectivity check: ipv6: %w", err)
	}

	defer func() {
		closeErr := connV6.Close()
		if closeErr != nil {
			log.Fatalf("connectivity check: ipv6: %v", closeErr)
		}
	}()

	return nil
}

// requireIPv6ConnCheck returns true if provided serverGroups require IPv6
// connectivity check.
func requireIPv6ConnCheck(serverGroups []*agd.ServerGroup) (ok bool) {
	for _, srvGrp := range serverGroups {
		for _, s := range srvGrp.Servers {
			if containsIPv6BindAddress(s.BindData) {
				return true
			}
		}
	}

	return false
}

// containsIPv6BindAddress returns true if provided bindData contains valid IPv6
// address.
func containsIPv6BindAddress(bindData []*agd.ServerBindData) (ok bool) {
	for _, bData := range bindData {
		if addr := bData.AddrPort; addr.Addr().Is6() {
			return true
		}
	}

	return false
}
