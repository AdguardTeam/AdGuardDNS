package cmd

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
)

// accessConfig is the configuration that controls IP and hosts blocking.
type accessConfig struct {
	// BlockedQuestionDomains is a list of AdBlock rules used to block access.
	BlockedQuestionDomains []string `yaml:"blocked_question_domains"`

	// BlockedClientSubnets is a list of IP addresses or subnets to block.
	BlockedClientSubnets []netutil.Prefix `yaml:"blocked_client_subnets"`
}

// type check
var _ validator = (*accessConfig)(nil)

// validate implements the [validator] interface for *accessConfig.
func (c *accessConfig) validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return nil
}
