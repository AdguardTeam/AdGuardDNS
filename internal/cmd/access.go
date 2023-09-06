package cmd

import (
	"fmt"
	"net/netip"
)

// accessConfig is the configuration that controls IP and hosts blocking.
type accessConfig struct {
	// BlockedQuestionDomains is a list of AdBlock rules used to block access.
	BlockedQuestionDomains []string `yaml:"blocked_question_domains"`

	// BlockedClientSubnets is a list of IP addresses or subnets to block.
	BlockedClientSubnets []string `yaml:"blocked_client_subnets"`
}

// validate returns an error if the access configuration is invalid.
func (a *accessConfig) validate() (err error) {
	if a == nil {
		return errNilConfig
	}

	for i, s := range a.BlockedClientSubnets {
		// TODO(a.garipov): Use [netutil.ParseSubnet] after refactoring it to
		// [netip.Addr].
		_, parseErr := netip.ParseAddr(s)
		if parseErr == nil {
			continue
		}

		_, parseErr = netip.ParsePrefix(s)
		if parseErr == nil {
			continue
		}

		return fmt.Errorf("value %q at index %d: bad ip or cidr: %w", s, i, parseErr)
	}

	return nil
}
