package agdnet

import (
	"crypto/tls"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// BindConfig is the configuration for binding a server to a network address.
type BindConfig struct {
	// ListenConfig is used to create listeners and packet connections for
	// server binding.
	ListenConfig netext.ListenConfig

	// TLS is the TLS configuration for the bind.  It must be nil or one of the
	// following types:
	//
	//  - [*BindConfigTLSDefault]
	//  - [*BindConfigTLSHTTPS]
	TLS BindConfigTLS

	// Addr is the network address to bind to.  It must not be nil and must be
	// one of the following types:
	//
	//   - [BindConfigAddrDefault]
	//   - [*BindConfigAddrPrefix]
	Addr BindConfigAddr
}

// BindConfigAddr is a sum type of all possible network binding addresses.  See
// the following types as implementations:
//
//   - [BindConfigAddrDefault]
//   - [*BindConfigAddrPrefix]
type BindConfigAddr interface {
	fmt.Stringer

	isBindConfigAddr()
}

// BindConfigAddrDefault is a single network address for a bind.
type BindConfigAddrDefault netip.AddrPort

// type check
var _ BindConfigAddr = BindConfigAddrDefault{}

// String implements the [BindConfigAddr] interface for BindConfigAddrDefault.
func (b BindConfigAddrDefault) String() (s string) {
	return netip.AddrPort(b).String()
}

// isBindConfigAddr implements the [BindConfigAddr] interface for
// BindConfigAddrDefault.
func (BindConfigAddrDefault) isBindConfigAddr() {}

// BindConfigAddrPrefix is a network prefix for a bind.
type BindConfigAddrPrefix PrefixNetAddr

// type check
var _ BindConfigAddr = (*BindConfigAddrPrefix)(nil)

// String implements the [BindConfigAddr] interface for
// *BindConfigAddrPrefix.
func (b *BindConfigAddrPrefix) String() (s string) {
	return (*PrefixNetAddr)(b).String()
}

// isBindConfigAddr implements the [BindConfigAddr] interface for
// *BindConfigAddrPrefix.
func (*BindConfigAddrPrefix) isBindConfigAddr() {}

// BindConfigs is a slice of server bind configurations.  Its elements must
// not be nil and must be valid.
type BindConfigs []*BindConfig

// HasAddr returns true if addr is within bind configs.  It does not check
// prefix addresses unless they are single-IP subnets.
func (b BindConfigs) HasAddr(addr netip.AddrPort) (ok bool) {
	for _, bc := range b {
		switch bindAddr := bc.Addr.(type) {
		case BindConfigAddrDefault:
			if netip.AddrPort(bindAddr) == addr {
				return true
			}
		case *BindConfigAddrPrefix:
			p := bindAddr.Prefix
			if p.IsSingleIP() && p.Addr() == addr.Addr() && bindAddr.Port == addr.Port() {
				return true
			}
		default:
			panic(fmt.Errorf("bind config: unexpected address type: %T(%[1]v)", bindAddr))
		}
	}

	return false
}

// HasIPv6 returns true if bind configs contain an IPv6 address.  If bind
// configs are empty, it returns false.
//
// NOTE: It only considers [BindConfigAddrDefault], skipping the prefix
// addresses.
func (b BindConfigs) HasIPv6() (ok bool) {
	for _, bc := range b {
		var addr netip.Addr
		switch bindAddr := bc.Addr.(type) {
		case BindConfigAddrDefault:
			addr = netip.AddrPort(bindAddr).Addr()
		case *BindConfigAddrPrefix:
			continue
		default:
			panic(fmt.Errorf("bind config: unexpected address type: %T(%[1]v)", bindAddr))
		}

		if addr.Is6() {
			return true
		}
	}

	return false
}

// Prefixes returns a slice of CIDR networks collected from the bind configs.
func (b BindConfigs) Prefixes() (ps []netip.Prefix) {
	for _, bc := range b {
		var pref netip.Prefix
		switch bindAddr := bc.Addr.(type) {
		case BindConfigAddrDefault:
			addr := netip.AddrPort(bindAddr).Addr()
			pref = netip.PrefixFrom(addr, addr.BitLen())
		case *BindConfigAddrPrefix:
			pref = bindAddr.Prefix
		default:
			panic(fmt.Errorf("bind config: unexpected address type: %T(%[1]v)", bindAddr))
		}

		ps = append(ps, pref)
	}

	return ps
}

// BindConfigTLS is a sum type of all possible network binding TLS
// configurations.  See the following types as implementations:
//
//   - [*BindConfigTLSDefault]
//   - [*BindConfigTLSHTTPS]
type BindConfigTLS interface{ isBindConfigTLS() }

// BindConfigTLSDefault is a single TLS configuration for a bind.
type BindConfigTLSDefault tls.Config

// type check
var _ BindConfigTLS = (*BindConfigTLSDefault)(nil)

// isBindConfigTLS implements the [BindConfigTLS] interface for
// *BindConfigTLSDefault.
func (*BindConfigTLSDefault) isBindConfigTLS() {}

// BindConfigTLSHTTPS contains the TLS configurations for an HTTPS bind.
type BindConfigTLSHTTPS struct {
	// Default is the TLS configuration for HTTP/1.1 and HTTP/2.  If HTTP3 is
	// nil, it must not be nil.
	Default *tls.Config

	// HTTP3 is the TLS configuration for HTTP/3.  If Default is nil, it must
	// not be nil.
	HTTP3 *tls.Config
}

// type check
var _ BindConfigTLS = (*BindConfigTLSHTTPS)(nil)

// isBindConfigTLS implements the [BindConfigTLS] interface for
// *BindConfigTLSHTTPS.
func (*BindConfigTLSHTTPS) isBindConfigTLS() {}

// TLSConfigFromBindConfig returns the default and HTTP3 TLS configurations from
// the TLS bind config.  If b is nil, it returns nil.  If b is
// [*BindConfigTLSDefault], http3Conf is nil.  If b is [*BindConfigTLSHTTPS] and
// b is valid, at least one of defaultConf or http3Conf is not nil.
func TLSConfigFromBindConfig(b BindConfigTLS) (defaultConf, http3Conf *tls.Config) {
	switch v := b.(type) {
	case nil:
		return nil, nil
	case *BindConfigTLSDefault:
		return (*tls.Config)(v), nil
	case *BindConfigTLSHTTPS:
		return v.Default, v.HTTP3
	default:
		panic(fmt.Errorf("bind config: unexpected type for bind tls config: %T(%[1]v)", v))
	}
}
