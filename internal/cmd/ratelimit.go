package cmd

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
)

// Rate Limiter Configuration

// rateLimitConfig is the configuration of the instance's rate limiting.
type rateLimitConfig struct {
	// AllowList is the allowlist of clients.
	Allowlist *allowListConfig `yaml:"allowlist"`

	// ResponseSizeEstimate is the size of the estimate of the size of one DNS
	// response for the purposes of rate limiting.  Responses over this estimate
	// are counted as several responses.
	ResponseSizeEstimate datasize.ByteSize `yaml:"response_size_estimate"`

	// RPS is the maximum number of requests per second.
	RPS int `yaml:"rps"`

	// BackOffCount helps with repeated offenders.  It defines, how many times
	// a client hits the rate limit before being held in the back off.
	BackOffCount int `yaml:"back_off_count"`

	// BackOffDuration is how much a client that has hit the rate limit too
	// often stays in the back off.
	BackOffDuration timeutil.Duration `yaml:"back_off_duration"`

	// BackOffPeriod is the time during which to count the number of times
	// a client has hit the rate limit for a back off.
	BackOffPeriod timeutil.Duration `yaml:"back_off_period"`

	// IPv4SubnetKeyLen is the length of the subnet prefix used to calculate
	// rate limiter bucket keys for IPv4 addresses.
	IPv4SubnetKeyLen int `yaml:"ipv4_subnet_key_len"`

	// IPv6SubnetKeyLen is the length of the subnet prefix used to calculate
	// rate limiter bucket keys for IPv6 addresses.
	IPv6SubnetKeyLen int `yaml:"ipv6_subnet_key_len"`

	// RefuseANY, if true, makes the server refuse DNS * queries.
	RefuseANY bool `yaml:"refuse_any"`
}

// toInternal converts c to the rate limiting configuration for the DNS server.
// c is assumed to be valid.
func (c *rateLimitConfig) toInternal(al ratelimit.Allowlist) (conf *ratelimit.BackOffConfig) {
	return &ratelimit.BackOffConfig{
		Allowlist:            al,
		ResponseSizeEstimate: int(c.ResponseSizeEstimate.Bytes()),
		Duration:             c.BackOffDuration.Duration,
		Period:               c.BackOffPeriod.Duration,
		RPS:                  c.RPS,
		Count:                c.BackOffCount,
		IPv4SubnetKeyLen:     c.IPv4SubnetKeyLen,
		IPv6SubnetKeyLen:     c.IPv6SubnetKeyLen,
		RefuseANY:            c.RefuseANY,
	}
}

// validate returns an error if the safe rate limiting configuration is invalid.
func (c *rateLimitConfig) validate() (err error) {
	// TODO(a.garipov): Refactor by grouping some checks together and using
	// generic helper functions.

	switch {
	case c == nil:
		return errNilConfig
	case c.RPS <= 0:
		return newMustBePositiveError("rps", c.RPS)
	case c.BackOffCount <= 0:
		return newMustBePositiveError("back_off_count", c.BackOffCount)
	case c.BackOffDuration.Duration <= 0:
		return newMustBePositiveError("back_off_duration", c.BackOffDuration)
	case c.BackOffPeriod.Duration <= 0:
		return newMustBePositiveError("back_off_period", c.BackOffPeriod)
	case c.ResponseSizeEstimate <= 0:
		return newMustBePositiveError("response_size_estimate", c.ResponseSizeEstimate)
	case c.Allowlist.RefreshIvl.Duration <= 0:
		return newMustBePositiveError("allowlist.refresh_interval", c.Allowlist.RefreshIvl)
	case c.IPv4SubnetKeyLen <= 0:
		return newMustBePositiveError("ipv4_subnet_key_len", c.IPv4SubnetKeyLen)
	case c.IPv6SubnetKeyLen <= 0:
		return newMustBePositiveError("ipv6_subnet_key_len", c.IPv6SubnetKeyLen)
	default:
		return nil
	}
}
