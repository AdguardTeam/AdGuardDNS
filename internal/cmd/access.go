package cmd

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/validate"
)

// Possible values of the STANDARD_ACCESS_TYPE environment variable.
const (
	standardAccessOff     = "off"
	standardAccessBackend = "backend"
)

// accessConfig is the configuration that controls IP and hosts blocking.
type accessConfig struct {
	// BlockedQuestionDomains is a list of AdBlock rules used to block access.
	BlockedQuestionDomains []string `yaml:"blocked_question_domains"`

	// BlockedClientSubnets is a list of IP addresses or subnets to block.
	BlockedClientSubnets []netutil.Prefix `yaml:"blocked_client_subnets"`
}

// type check
var _ validate.Interface = (*accessConfig)(nil)

// Validate implements the [validate.Interface] interface for *accessConfig.
func (c *accessConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return nil
}
