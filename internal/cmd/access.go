package cmd

import (
	"github.com/AdguardTeam/golibs/netutil"
)

// accessConfig is the configuration that controls IP and hosts blocking.
type accessConfig struct {
	// BlockedQuestionDomains is a list of AdBlock rules used to block access.
	BlockedQuestionDomains []string `yaml:"blocked_question_domains"`

	// BlockedClientSubnets is a list of IP addresses or subnets to block.
	BlockedClientSubnets []netutil.Prefix `yaml:"blocked_client_subnets"`
}

// validate returns an error if the access configuration is invalid.
func (a *accessConfig) validate() (err error) {
	if a == nil {
		return errNilConfig
	}

	return nil
}
