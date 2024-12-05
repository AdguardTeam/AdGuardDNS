package agd

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/ameshkov/dnscrypt/v2"
)

// Server represents a single DNS server.  That is, an entity that binds to one
// or more ports and serves DNS over a single protocol.
type Server struct {
	// DNSCrypt are the DNSCrypt settings for this server, if any.
	DNSCrypt *DNSCryptConfig

	// TLS is the TLS configuration for this server, if any.
	TLS *TLSConfig

	// QUICConf is the QUIC configuration for this server.
	QUICConf *QUICConfig

	// TCPConf is the TCP configuration for this server.
	TCPConf *TCPConfig

	// UDPConf is the UDP configuration for this server.
	UDPConf *UDPConfig

	// Name is the unique name of the server.  Not to be confused with a TLS
	// Server Name.
	Name ServerName

	// bindData are the socket binding data for this server.
	bindData []*ServerBindData

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

// BindData returns the bind data of this server.  The elements of the slice
// must not be mutated.
func (s *Server) BindData() (data []*ServerBindData) {
	return s.bindData
}

// SetBindData sets the bind data of this server.  data must have at least one
// element and all of its elements must be of the same underlying type.  The
// elements of data must not be mutated after calling SetBindData.
func (s *Server) SetBindData(data []*ServerBindData) {
	switch len(data) {
	case 0:
		panic(errors.Error("empty bind data"))
	case 1:
		s.bindData = data
	default:
		firstIsAddrPort := data[0].PrefixAddr == nil
		for i, bd := range data[1:] {
			if (bd.PrefixAddr == nil) != firstIsAddrPort {
				panic(fmt.Errorf("at index %d: inconsistent type of bind data", i+1))
			}
		}

		s.bindData = data
	}
}

// HasAddr returns true if addr is within the server's bind data.  HasAddr does
// not check prefix addresses unless they are single-IP subnets.
func (s *Server) HasAddr(addr netip.AddrPort) (ok bool) {
	for _, bd := range s.bindData {
		prefAddr := bd.PrefixAddr
		if prefAddr == nil {
			if bd.AddrPort == addr {
				return true
			}

			continue
		}

		p := prefAddr.Prefix
		if p.IsSingleIP() && p.Addr() == addr.Addr() && prefAddr.Port == addr.Port() {
			return true
		}
	}

	return false
}

// HasIPv6 returns true if the bind data of this server contains an IPv6
// address.  For a server with no bind data, HasIPv6 returns false.
func (s *Server) HasIPv6() (ok bool) {
	for _, bd := range s.bindData {
		if bd.AddrPort.Addr().Is6() {
			return true
		}
	}

	return false
}

// BindsToInterfaces returns true if server binds to interfaces.  For a server
// with no bind data, BindsToInterfaces returns false.
func (s *Server) BindsToInterfaces() (ok bool) {
	return len(s.bindData) > 0 && s.bindData[0].PrefixAddr != nil
}

// BindDataPrefixes returns a slice of CIDR networks collected from the bind
// data of this server.
func (s *Server) BindDataPrefixes() (ps []netip.Prefix) {
	for _, bd := range s.bindData {
		var pref netip.Prefix
		if bd.PrefixAddr == nil {
			addr := bd.AddrPort.Addr()
			pref = netip.PrefixFrom(addr, addr.BitLen())
		} else {
			pref = bd.PrefixAddr.Prefix
		}

		ps = append(ps, pref)
	}

	return ps
}

// ServerBindData are the socket binding data for a server.  Either AddrPort or
// ListenConfig with PrefixAddr must be set.
//
// TODO(a.garipov): Consider turning this into a sum type.
//
// TODO(a.garipov): Consider renaming this and the one in websvc to something
// like BindConfig.
type ServerBindData struct {
	ListenConfig netext.ListenConfig
	PrefixAddr   *agdnet.PrefixNetAddr

	AddrPort netip.AddrPort
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

// TLSConfig is the TLS configuration of a DNS server.  Metrics and ALPs must be
// set for saved configurations.
type TLSConfig struct {
	// Default is the defult TLS configuration.  It must not be nil.
	Default *tls.Config

	// H3 is the TLS configuration for DoH3.
	H3 *tls.Config
}
