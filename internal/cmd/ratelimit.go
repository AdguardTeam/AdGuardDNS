package cmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
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

// rateLimitOptions allows define maximum number of requests for IPv4 or IPv6
// addresses.
type rateLimitOptions struct {
	// Count is the maximum number of requests per interval.
	Count uint `yaml:"count"`

	// Interval is the time during which to count the number of requests.
	Interval timeutil.Duration `yaml:"interval"`

	// SubnetKeyLen is the length of the subnet prefix used to calculate
	// rate limiter bucket keys.
	SubnetKeyLen int `yaml:"subnet_key_len"`
}

// type check
var _ validate.Interface = (*rateLimitOptions)(nil)

// Validate implements the [validate.Interface] interface for *rateLimitOptions.
func (o *rateLimitOptions) Validate() (err error) {
	if o == nil {
		return errors.ErrNoValue
	}

	return errors.Join(
		validate.Positive("count", o.Count),
		validate.Positive("interval", o.Interval),
		validate.Positive("subnet_key_len", o.SubnetKeyLen),
	)
}

// toInternal converts c to the rate limiting configuration for the DNS server.
// c must be valid.
func (c *rateLimitConfig) toInternal(al ratelimit.Allowlist) (conf *ratelimit.BackoffConfig) {
	return &ratelimit.BackoffConfig{
		Allowlist:            al,
		ResponseSizeEstimate: c.ResponseSizeEstimate,
		Duration:             time.Duration(c.BackoffDuration),
		Period:               time.Duration(c.BackoffPeriod),
		IPv4Count:            c.IPv4.Count,
		IPv4Interval:         time.Duration(c.IPv4.Interval),
		IPv4SubnetKeyLen:     c.IPv4.SubnetKeyLen,
		IPv6Count:            c.IPv6.Count,
		IPv6Interval:         time.Duration(c.IPv6.Interval),
		IPv6SubnetKeyLen:     c.IPv6.SubnetKeyLen,
		Count:                c.BackoffCount,
		RefuseANY:            c.RefuseANY,
	}
}

// type check
var _ validate.Interface = (*rateLimitConfig)(nil)

// Validate implements the [validate.Interface] interface for *rateLimitConfig.
func (c *rateLimitConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.Positive("backoff_count", c.BackoffCount),
		validate.Positive("backoff_duration", c.BackoffDuration),
		validate.Positive("backoff_period", c.BackoffPeriod),
		validate.Positive("response_size_estimate", c.ResponseSizeEstimate),
	}

	errs = validate.Append(errs, "allowlist", c.Allowlist)
	errs = validate.Append(errs, "connection_limit", c.ConnectionLimit)
	errs = validate.Append(errs, "ipv4", c.IPv4)
	errs = validate.Append(errs, "ipv6", c.IPv6)
	errs = validate.Append(errs, "quic", c.QUIC)
	errs = validate.Append(errs, "tcp", c.TCP)

	return errors.Join(errs...)
}

// allowListConfig is the consul allow list configuration.
type allowListConfig struct {
	// List contains IPs and CIDRs.
	List []netutil.Prefix `yaml:"list"`

	// RefreshIvl time between two updates of allow list from the Consul URL.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`
}

// Constants for rate limit settings endpoints.
const (
	rlAllowlistTypeBackend = "backend"
	rlAllowlistTypeConsul  = "consul"
)

// type check
var _ validate.Interface = (*allowListConfig)(nil)

// Validate implements the [validate.Interface] interface for *allowListConfig.
func (c *allowListConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return validate.Positive("refresh_interval", c.RefreshIvl)
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

// toInternal converts c to a valid connection limiter config.  c must be valid.
// mtrc must not be nil.
func (c *connLimitConfig) toInternal(
	ctx context.Context,
	logger *slog.Logger,
	mtrc connlimiter.Metrics,
) (l *connlimiter.Config) {
	mtrc.SetStopLimit(ctx, c.Stop)
	mtrc.SetResumeLimit(ctx, c.Resume)

	return &connlimiter.Config{
		Metrics: mtrc,
		Logger:  logger.With(slogutil.KeyPrefix, "connlimiter"),
		Stop:    c.Stop,
		Resume:  c.Resume,
	}
}

// type check
var _ validate.Interface = (*connLimitConfig)(nil)

// Validate implements the [validate.Interface] interface for *connLimitConfig.
func (c *connLimitConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	} else if !c.Enabled {
		return nil
	}

	return errors.Join(
		validate.Positive("stop", c.Stop),
		validate.Positive("resume", c.Resume),
		validate.NoGreaterThan("resume", c.Resume, c.Stop),
	)
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
var _ validate.Interface = (*ratelimitTCPConfig)(nil)

// Validate implements the [validate.Interface] interface for *ratelimitTCPConfig.
func (c *ratelimitTCPConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return validate.Positive("max_pipeline_count", c.MaxPipelineCount)
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
var _ validate.Interface = (*ratelimitQUICConfig)(nil)

// Validate implements the [validate.Interface] interface for *ratelimitQUICConfig.
func (c *ratelimitQUICConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return validate.Positive("max_streams_per_peer", c.MaxStreamsPerPeer)
}
