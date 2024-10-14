package cmd

import (
	"cmp"
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
)

// rateLimitConfig is the configuration of the instance's rate limiting.
type rateLimitConfig struct {
	// AllowList is the allowlist of clients.
	Allowlist *allowListConfig `yaml:"allowlist"`

	// ConnectionLimit is the configuration for the limits on stream
	// connections.
	ConnectionLimit *connLimitConfig `yaml:"connection_limit"`

	// Rate limit options for IPv4 addresses.
	IPv4 *rateLimitOptions `yaml:"ipv4"`

	// Rate limit options for IPv6 addresses.
	IPv6 *rateLimitOptions `yaml:"ipv6"`

	// QUIC is the configuration of QUIC streams limiting.
	QUIC *ratelimitQUICConfig `yaml:"quic"`

	// TCP is the configuration of TCP pipeline limiting.
	TCP *ratelimitTCPConfig `yaml:"tcp"`

	// ResponseSizeEstimate is the estimate of the size of one DNS response for
	// the purposes of rate limiting.  Responses over this estimate are counted
	// as several responses.
	ResponseSizeEstimate datasize.ByteSize `yaml:"response_size_estimate"`

	// BackoffCount helps with repeated offenders.  It defines, how many times
	// a client hits the rate limit before being held in the back off.
	BackoffCount uint `yaml:"backoff_count"`

	// BackoffDuration is how much a client that has hit the rate limit too
	// often stays in the back off.
	BackoffDuration timeutil.Duration `yaml:"backoff_duration"`

	// BackoffPeriod is the time during which to count the number of times
	// a client has hit the rate limit for a back off.
	BackoffPeriod timeutil.Duration `yaml:"backoff_period"`

	// RefuseANY, if true, makes the server refuse DNS * queries.
	RefuseANY bool `yaml:"refuse_any"`
}

// allowListConfig is the consul allow list configuration.
type allowListConfig struct {
	// List contains IPs and CIDRs.
	List []netutil.Prefix `yaml:"list"`

	// RefreshIvl time between two updates of allow list from the Consul URL.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`
}

// rateLimitOptions allows define maximum number of requests for IPv4 or IPv6
// addresses.
type rateLimitOptions struct {
	// RPS is the maximum number of requests per second.
	RPS uint `yaml:"rps"`

	// SubnetKeyLen is the length of the subnet prefix used to calculate
	// rate limiter bucket keys.
	SubnetKeyLen int `yaml:"subnet_key_len"`
}

// type check
var _ validator = (*rateLimitOptions)(nil)

// validate implements the [validator] interface for *rateLimitOptions.
func (o *rateLimitOptions) validate() (err error) {
	if o == nil {
		return errors.ErrNoValue
	}

	return cmp.Or(
		validatePositive("rps", o.RPS),
		validatePositive("subnet_key_len", o.SubnetKeyLen),
	)
}

// toInternal converts c to the rate limiting configuration for the DNS server.
// c must be valid.
func (c *rateLimitConfig) toInternal(al ratelimit.Allowlist) (conf *ratelimit.BackoffConfig) {
	return &ratelimit.BackoffConfig{
		Allowlist:            al,
		ResponseSizeEstimate: c.ResponseSizeEstimate,
		Duration:             c.BackoffDuration.Duration,
		Period:               c.BackoffPeriod.Duration,
		IPv4RPS:              c.IPv4.RPS,
		IPv4SubnetKeyLen:     c.IPv4.SubnetKeyLen,
		IPv6RPS:              c.IPv6.RPS,
		IPv6SubnetKeyLen:     c.IPv6.SubnetKeyLen,
		Count:                c.BackoffCount,
		RefuseANY:            c.RefuseANY,
	}
}

// type check
var _ validator = (*rateLimitConfig)(nil)

// validate implements the [validator] interface for *rateLimitConfig.
func (c *rateLimitConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.Allowlist == nil:
		return fmt.Errorf("allowlist: %w", errors.ErrNoValue)
	}

	return cmp.Or(
		validateProp("connection_limit", c.ConnectionLimit.validate),
		validateProp("ipv4", c.IPv4.validate),
		validateProp("ipv6", c.IPv6.validate),
		validateProp("quic", c.QUIC.validate),
		validateProp("tcp", c.TCP.validate),
		validatePositive("backoff_count", c.BackoffCount),
		validatePositive("backoff_duration", c.BackoffDuration),
		validatePositive("backoff_period", c.BackoffPeriod),
		validatePositive("response_size_estimate", c.ResponseSizeEstimate),
		validatePositive("allowlist.refresh_interval", c.Allowlist.RefreshIvl),
	)
}

// connLimitConfig is the configuration structure for the stream-connection
// limiter.
type connLimitConfig struct {
	// Stop is the point at which the limiter stops accepting new connections.
	// Once the number of active connections reaches this limit, new connections
	// wait for the number to decrease below Resume.
	//
	// Stop must be greater than zero and greater than or equal to Resume.
	Stop uint64 `yaml:"stop"`

	// Resume is the point at which the limiter starts accepting new connections
	// again.
	//
	// Resume must be greater than zero and less than or equal to Stop.
	Resume uint64 `yaml:"resume"`

	// Enabled, if true, enables stream-connection limiting.
	Enabled bool `yaml:"enabled"`
}

// toInternal converts c to the connection limiter to use.  c must be valid.
func (c *connLimitConfig) toInternal(logger *slog.Logger) (l *connlimiter.Limiter) {
	if !c.Enabled {
		return nil
	}

	l, err := connlimiter.New(&connlimiter.Config{
		Logger: logger.With(slogutil.KeyPrefix, "connlimiter"),
		Stop:   c.Stop,
		Resume: c.Resume,
	})
	if err != nil {
		panic(err)
	}

	metrics.ConnLimiterLimits.WithLabelValues("stop").Set(float64(c.Stop))
	metrics.ConnLimiterLimits.WithLabelValues("resume").Set(float64(c.Resume))

	return l
}

// type check
var _ validator = (*connLimitConfig)(nil)

// validate implements the [validator] interface for *connLimitConfig.
func (c *connLimitConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case !c.Enabled:
		return nil
	case c.Stop == 0:
		return newNotPositiveError("stop", c.Stop)
	case c.Resume > c.Stop:
		return errors.Error("resume: must be less than or equal to stop")
	default:
		return nil
	}
}

// ratelimitTCPConfig is the configuration of TCP pipeline limiting.
type ratelimitTCPConfig struct {
	// MaxPipelineCount is the maximum number of simultaneously processing TCP
	// messages per one connection.
	MaxPipelineCount uint `yaml:"max_pipeline_count"`

	// Enabled, if true, enables TCP limiting.
	Enabled bool `yaml:"enabled"`
}

// type check
var _ validator = (*ratelimitTCPConfig)(nil)

// validate implements the [validator] interface for *ratelimitTCPConfig.
func (c *ratelimitTCPConfig) validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return validatePositive("max_pipeline_count", c.MaxPipelineCount)
}

// ratelimitQUICConfig is the configuration of QUIC streams limiting.
type ratelimitQUICConfig struct {
	// MaxStreamsPerPeer is the maximum number of concurrent streams that a peer
	// is allowed to open.
	MaxStreamsPerPeer int `yaml:"max_streams_per_peer"`

	// Enabled, if true, enables QUIC limiting.
	Enabled bool `yaml:"enabled"`
}

// type check
var _ validator = (*ratelimitQUICConfig)(nil)

// validate implements the [validator] interface for *ratelimitQUICConfig.
func (c *ratelimitQUICConfig) validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return validatePositive("max_streams_per_peer", c.MaxStreamsPerPeer)
}
