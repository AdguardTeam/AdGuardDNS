package cmd

import (
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
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
var _ validate.Interface = (*dnsConfig)(nil)

// Validate implements the [validate.Interface] interface for *dnsConfig.
func (c *dnsConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return errors.Join(
		validate.Positive("read_timeout", c.ReadTimeout),
		validate.Positive("tcp_idle_timeout", c.TCPIdleTimeout),
		validate.NoGreaterThan(
			"tcp_idle_timeout",
			time.Duration(c.TCPIdleTimeout),
			dnsserver.MaxTCPIdleTimeout,
		),
		validate.Positive("write_timeout", c.WriteTimeout),
		validate.Positive("handle_timeout", c.HandleTimeout),
		validate.Positive("max_udp_response_size", c.MaxUDPResponseSize),
		validate.NoGreaterThan("max_udp_response_size", c.MaxUDPResponseSize, dns.MaxMsgSize),
	)
}
