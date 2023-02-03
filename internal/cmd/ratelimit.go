package cmd

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
)

// Rate Limiter Configuration

// rateLimitConfig is the configuration of the instance's rate limiting.
type rateLimitConfig struct {
	// AllowList is the allowlist of clients.
	Allowlist *allowListConfig `yaml:"allowlist"`

	// Rate limit options for IPv4 addresses.
	IPv4 *rateLimitOptions `yaml:"ipv4"`

	// Rate limit options for IPv6 addresses.
	IPv6 *rateLimitOptions `yaml:"ipv6"`

	// ResponseSizeEstimate is the size of the estimate of the size of one DNS
	// response for the purposes of rate limiting.  Responses over this estimate
	// are counted as several responses.
	ResponseSizeEstimate datasize.ByteSize `yaml:"response_size_estimate"`

	// BackOffCount helps with repeated offenders.  It defines, how many times
	// a client hits the rate limit before being held in the back off.
	BackOffCount int `yaml:"back_off_count"`

	// BackOffDuration is how much a client that has hit the rate limit too
	// often stays in the back off.
	BackOffDuration timeutil.Duration `yaml:"back_off_duration"`

	// BackOffPeriod is the time during which to count the number of times
	// a client has hit the rate limit for a back off.
	BackOffPeriod timeutil.Duration `yaml:"back_off_period"`

	// RefuseANY, if true, makes the server refuse DNS * queries.
	RefuseANY bool `yaml:"refuse_any"`
}

// allowListConfig is the consul allow list configuration.
type allowListConfig struct {
	// List contains IPs and CIDRs.
	List []string `yaml:"list"`

	// RefreshIvl time between two updates of allow list from the Consul URL.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`
}

// rateLimitOptions allows define maximum number of requests for IPv4 or IPv6
// addresses.
type rateLimitOptions struct {
	// RPS is the maximum number of requests per second.
	RPS int `yaml:"rps"`

	// SubnetKeyLen is the length of the subnet prefix used to calculate
	// rate limiter bucket keys.
	SubnetKeyLen int `yaml:"subnet_key_len"`
}

// validate returns an error if rate limit options are invalid.
func (o *rateLimitOptions) validate() (err error) {
	if o == nil {
		return errNilConfig
	}

	return coalesceError(
		validatePositive("rps", o.RPS),
		validatePositive("subnet_key_len", o.SubnetKeyLen),
	)
}

// toInternal converts c to the rate limiting configuration for the DNS server.
// c is assumed to be valid.
func (c *rateLimitConfig) toInternal(al ratelimit.Allowlist) (conf *ratelimit.BackOffConfig) {
	return &ratelimit.BackOffConfig{
		Allowlist:            al,
		ResponseSizeEstimate: int(c.ResponseSizeEstimate.Bytes()),
		Duration:             c.BackOffDuration.Duration,
		Period:               c.BackOffPeriod.Duration,
		IPv4RPS:              c.IPv4.RPS,
		IPv4SubnetKeyLen:     c.IPv4.SubnetKeyLen,
		IPv6RPS:              c.IPv6.RPS,
		IPv6SubnetKeyLen:     c.IPv6.SubnetKeyLen,
		Count:                c.BackOffCount,
		RefuseANY:            c.RefuseANY,
	}
}

// validate returns an error if the safe rate limiting configuration is invalid.
func (c *rateLimitConfig) validate() (err error) {
	if c == nil {
		return errNilConfig
	} else if c.Allowlist == nil {
		return fmt.Errorf("allowlist: %w", errNilConfig)
	}

	err = c.IPv4.validate()
	if err != nil {
		return fmt.Errorf("ipv4: %w", err)
	}

	err = c.IPv6.validate()
	if err != nil {
		return fmt.Errorf("ipv6: %w", err)
	}

	return coalesceError(
		validatePositive("back_off_count", c.BackOffCount),
		validatePositive("back_off_duration", c.BackOffDuration),
		validatePositive("back_off_period", c.BackOffPeriod),
		validatePositive("response_size_estimate", c.ResponseSizeEstimate),
		validatePositive("allowlist.refresh_interval", c.Allowlist.RefreshIvl),
	)
}
