package agd

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// Servers And Server Groups

// ServerGroup is a group of DNS servers all of which use the same filtering
// settings.
type ServerGroup struct {
	// TLS are the TLS settings for this server group.  If Servers contains at
	// least one server with a non-plain protocol (see [Protocol.IsPlain]), TLS
	// must not be nil.
	TLS *TLS

	// DDR is the configuration for the server group's Discovery Of Designated
	// Resolvers (DDR) handlers.  DDR is never nil.
	DDR *DDR

	// Name is the unique name of the server group.
	Name ServerGroupName

	// FilteringGroup is the ID of the filtering group for this server.
	FilteringGroup FilteringGroupID

	// Servers are the settings for servers.  Each element must be non-nil.
	Servers []*Server
}

// ServerGroupName is the name of a server group.
type ServerGroupName string

// TLS is the TLS configuration of a DNS server group.
type TLS struct {
	// Conf is the server's TLS configuration.
	Conf *tls.Config

	// DeviceIDWildcards are the domain wildcards used to detect device IDs from
	// clients' server names.
	DeviceIDWildcards []string

	// SessionKeys are paths to files containing the TLS session keys for this
	// server.
	SessionKeys []string
}

// DDR is the configuration for the server group's Discovery Of Designated
// Resolvers (DDR) handlers.
type DDR struct {
	// DeviceTargets is the set of all domain names, subdomains of which should
	// be checked for DDR queries with device IDs.
	DeviceTargets *stringutil.Set

	// PublicTargets is the set of all public domain names, DDR queries for
	// which should be processed.
	PublicTargets *stringutil.Set

	// DeviceRecordTemplates are used to respond to DDR queries from recognized
	// devices.
	DeviceRecordTemplates []*dns.SVCB

	// PubilcRecordTemplates are used to respond to DDR queries from
	// unrecognized devices.
	PublicRecordTemplates []*dns.SVCB

	// Enabled shows if DDR queries are processed.  If it is false, DDR domain
	// name queries receive an NXDOMAIN response.
	Enabled bool
}

// Server represents a single DNS server.  That is, an entity that binds to one
// or more ports and serves DNS over a single protocol.
type Server struct {
	// DNSCrypt are the DNSCrypt settings for this server, if any.
	DNSCrypt *DNSCryptConfig

	// TLS is the TLS configuration for this server, if any.
	TLS *tls.Config

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
