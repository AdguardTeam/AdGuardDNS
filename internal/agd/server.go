package agd

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/ameshkov/dnscrypt/v2"
)

// Server represents a single DNS server.  That is, an entity that binds to one
// or more ports and serves DNS over a single protocol.
type Server struct {
	// DNSCrypt are the DNSCrypt settings for this server, if any.
	DNSCrypt *DNSCryptConfig

	// QUICConf is the QUIC configuration for this server.
	QUICConf *QUICConfig

	// TCPConf is the TCP configuration for this server.
	TCPConf *TCPConfig

	// UDPConf is the UDP configuration for this server.
	UDPConf *UDPConfig

	// Name is the unique name of the server.  Not to be confused with a TLS
	// Server Name.
	Name ServerName

	// bindConfigs are the socket binding data for this server.
	bindConfigs agdnet.BindConfigs

	// ReadTimeout defines the timeout for any read from a UDP connection or the
	// first read from a TCP/TLS connection.  It currently doesn't affect
	// DNSCrypt, QUIC, or HTTPS.
	//
	// TODO(a.garipov): Make it work for DNSCrypt, QUIC, and HTTPS.
	ReadTimeout time.Duration `yaml:"read_timeout"`

	// WriteTimeout defines the timeout for writing to a UDP or TCP/TLS
	// connection.  It currently doesn't affect DNSCrypt, QUIC, or HTTPS.
	//
	// TODO(a.garipov): Make it work for DNSCrypt, QUIC, and HTTPS.
	WriteTimeout time.Duration `yaml:"write_timeout"`

	// Protocol is the protocol of the server.
	Protocol Protocol

	// LinkedIPEnabled shows if the linked IP addresses should be used to detect
	// profiles on this server.
	LinkedIPEnabled bool
}

// BindConfigs returns slice of bind configs of this server.  The elements of
// the slice must not be mutated.
func (s *Server) BindConfigs() (data agdnet.BindConfigs) {
	return s.bindConfigs
}

// SetBindConfigs sets the bind configs for this server.  configs must have at
// least one element and all of its elements must be of the same underlying
// type.  The elements of configs must not be mutated after calling
// SetBindConfigs.
func (s *Server) SetBindConfigs(configs agdnet.BindConfigs) {
	switch len(configs) {
	case 0:
		panic(fmt.Errorf("bind config: %w", errors.ErrEmptyValue))
	case 1:
		s.bindConfigs = configs
	default:
		_, firstIsDefault := configs[0].Addr.(agdnet.BindConfigAddrDefault)
		for i, bd := range configs[1:] {
			_, isDefault := bd.Addr.(agdnet.BindConfigAddrDefault)
			if isDefault != firstIsDefault {
				panic(newInconsistentBindAddressTypeError(i, bd.Addr))
			}
		}

		s.bindConfigs = configs
	}
}

// newInconsistentBindAddressTypeError returns new bind address type
// inconsistency error.
func newInconsistentBindAddressTypeError(i int, addr agdnet.BindConfigAddr) (err error) {
	return fmt.Errorf(
		"setting bind configs: at index %d: inconsistent type of bind config address: %T",
		i+1,
		addr,
	)
}

// BindsToInterfaces returns true if server binds to interfaces.  For a server
// with no bind configs, BindsToInterfaces returns false.
func (s *Server) BindsToInterfaces() (ok bool) {
	if len(s.bindConfigs) == 0 {
		return false
	}

	_, ok = s.bindConfigs[0].Addr.(*agdnet.BindConfigAddrPrefix)

	return ok
}

// ServerName is the name of a server.
type ServerName string

// DNSCryptConfig is the DNSCrypt configuration of a DNS server.
type DNSCryptConfig struct {
	// Cert is the DNSCrypt certificate.
	Cert *dnscrypt.Cert

	// ProviderName is the name of the DNSCrypt provider.
	ProviderName string
}

// TCPConfig is the TCP configuration of a DNS server.
type TCPConfig struct {
	// IdleTimeout defines the timeout for consecutive reads from a TCP/TLS
	// connection.
	IdleTimeout time.Duration

	// MaxPipelineCount is the maximum number of simultaneously processing TCP
	// messages per one connection.  If MaxPipelineEnabled is true, it must be
	// greater than zero.
	MaxPipelineCount uint

	// MaxPipelineEnabled, if true, enables TCP pipeline limiting.
	MaxPipelineEnabled bool
}

// UDPConfig is the UDP configuration of a DNS server.
type UDPConfig struct {
	// MaxRespSize is the maximum size in bytes of DNS response over UDP
	// protocol.
	MaxRespSize uint16
}

// QUICConfig is the QUIC configuration of a DNS server.
type QUICConfig struct {
	// MaxStreamsPerPeer is the maximum number of concurrent streams that a peer
	// is allowed to open.
	MaxStreamsPerPeer int

	// QUICLimitsEnabled, if true, enables QUIC limiting.
	QUICLimitsEnabled bool
}
