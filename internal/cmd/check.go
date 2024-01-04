package cmd

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// DNS server check configuration

// checkConfig is the DNS server checking configuration.
type checkConfig struct {
	// Domains are the domain names used for DNS server checking.
	Domains []string `yaml:"domains"`

	// NodeLocation is the location of this server node.
	NodeLocation string `yaml:"node_location"`

	// NodeName is the name of this server node.
	NodeName string `yaml:"node_name"`

	// IPv4 is the list of IPv4 addresses to respond with for A queries to
	// subdomains of Domain.
	IPv4 []netip.Addr `yaml:"ipv4"`

	// IPv6 is the list of IPv6 addresses to respond with for AAAA queries to
	// subdomains of Domain.
	IPv6 []netip.Addr `yaml:"ipv6"`

	// TTL defines, for how long to keep the information about a single client.
	TTL timeutil.Duration `yaml:"ttl"`
}

// toInternal converts c to the DNS server check configuration for the DNS
// server.  c is assumed to be valid.
func (c *checkConfig) toInternal(
	envs *environments,
	messages *dnsmsg.Constructor,
	errColl errcoll.Interface,
) (conf *dnscheck.ConsulConfig) {
	var kvURL, sessURL *url.URL
	if envs.ConsulDNSCheckKVURL != nil && envs.ConsulDNSCheckSessionURL != nil {
		kvURL = netutil.CloneURL(&envs.ConsulDNSCheckKVURL.URL)
		sessURL = netutil.CloneURL(&envs.ConsulDNSCheckSessionURL.URL)
	}

	domains := make([]string, len(c.Domains))
	for i, d := range c.Domains {
		domains[i] = strings.ToLower(d)
	}

	return &dnscheck.ConsulConfig{
		Messages:         messages,
		ConsulKVURL:      kvURL,
		ConsulSessionURL: sessURL,
		ErrColl:          errColl,
		Domains:          domains,
		NodeLocation:     c.NodeLocation,
		NodeName:         c.NodeName,
		IPv4:             c.IPv4,
		IPv6:             c.IPv6,
		TTL:              c.TTL.Duration,
	}
}

// validate returns an error if the DNS server checking configuration is
// invalid.
func (c *checkConfig) validate() (err error) {
	if c == nil {
		return errNilConfig
	}

	notEmptyParams := []struct {
		name  string
		value string
	}{{
		name:  "node_location",
		value: c.NodeLocation,
	}, {
		name:  "node_name",
		value: c.NodeName,
	}}

	for _, param := range notEmptyParams {
		if param.value == "" {
			return fmt.Errorf("no %s", param.name)
		}
	}

	if len(c.Domains) == 0 {
		return errors.Error("no domains")
	}

	err = validateNonNilIPs(c.IPv4, netutil.AddrFamilyIPv4)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = validateNonNilIPs(c.IPv6, netutil.AddrFamilyIPv6)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if c.TTL.Duration <= 0 {
		return newMustBePositiveError("ttl", c.TTL)
	}

	return nil
}

// validateNonNilIPs returns an error if ips is empty or had IP addresses of
// incorrect protocol version.
//
// TODO(a.garipov): Merge with [validateAddrs].
func validateNonNilIPs(ips []netip.Addr, fam netutil.AddrFamily) (err error) {
	if len(ips) == 0 {
		return fmt.Errorf("no %s", fam)
	}

	// Assume that since ips are parsed from YAML, they are valid.

	var checkProto func(ip netip.Addr) (ok bool)
	switch fam {
	case netutil.AddrFamilyIPv4:
		checkProto = netip.Addr.Is4
	case netutil.AddrFamilyIPv6:
		checkProto = netip.Addr.Is6
	default:
		panic(fmt.Errorf("agdnet: unsupported addr fam %s", fam))
	}

	for i, ip := range ips {
		if !checkProto(ip) {
			return fmt.Errorf("%s: address %q at index %d: incorrect protocol", fam, ip, i)
		}
	}

	return nil
}
