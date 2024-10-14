package cmd

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
	"github.com/miekg/dns"
)

// dnsConfig contains common DNS settings.
type dnsConfig struct {
	// ReadTimeout defines the timeout for any read from a UDP connection or the
	// first read from a TCP/TLS connection.  It currently doesn't affect
	// DNSCrypt, QUIC, or HTTPS.
	ReadTimeout timeutil.Duration `yaml:"read_timeout"`

	// TCPIdleTimeout defines the timeout for consecutive reads from a TCP/TLS
	// connection.  It currently doesn't affect DNSCrypt, QUIC, or HTTPS.
	TCPIdleTimeout timeutil.Duration `yaml:"tcp_idle_timeout"`

	// WriteTimeout defines the timeout for writing to a UDP or TCP/TLS
	// connection.  It currently doesn't affect DNSCrypt, QUIC, or HTTPS.
	WriteTimeout timeutil.Duration `yaml:"write_timeout"`

	// HandleTimeout defines the timeout for the entire handling of a single
	// query.
	HandleTimeout timeutil.Duration `yaml:"handle_timeout"`

	// MaxUDPResponseSize is the maximum size of DNS response over UDP protocol.
	MaxUDPResponseSize datasize.ByteSize `yaml:"max_udp_response_size"`
}

// type check
var _ validator = (*dnsConfig)(nil)

// validate implements the [validator] interface for *dnsConfig.
func (c *dnsConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.ReadTimeout.Duration <= 0:
		return newNotPositiveError("read_timeout", c.ReadTimeout)
	case c.TCPIdleTimeout.Duration <= 0:
		return newNotPositiveError("tcp_idle_timeout", c.TCPIdleTimeout)
	case c.TCPIdleTimeout.Duration > dnsserver.MaxTCPIdleTimeout:
		return fmt.Errorf(
			"tcp_idle_timeout: %w: must be less than or equal to %s got %s",
			errors.ErrOutOfRange,
			dnsserver.MaxTCPIdleTimeout,
			c.TCPIdleTimeout,
		)
	case c.WriteTimeout.Duration <= 0:
		return newNotPositiveError("write_timeout", c.WriteTimeout)
	case c.HandleTimeout.Duration <= 0:
		return newNotPositiveError("handle_timeout", c.HandleTimeout)
	case c.MaxUDPResponseSize.Bytes() == 0:
		return newNotPositiveError("max_udp_response_size", c.MaxUDPResponseSize)
	case c.MaxUDPResponseSize.Bytes() > dns.MaxMsgSize:
		return fmt.Errorf(
			"max_udp_response_size must be less than %s, got %s",
			datasize.ByteSize(dns.MaxMsgSize),
			c.MaxUDPResponseSize,
		)
	default:
		return nil
	}
}
