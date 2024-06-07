package dnsserver

import (
	"fmt"
	"net"
	"slices"
)

// Protocol is a DNS protocol.
type Protocol uint8

// Protocol values.
const (
	// NOTE: DO NOT change the numerical values or use iota, because other
	// packages and modules may depend on the numerical values.  These numerical
	// values are a part of the API.

	// ProtoInvalid is the invalid default value.
	ProtoInvalid Protocol = 0

	// ProtoDNS is plain DNS.
	ProtoDNS Protocol = 8

	// ProtoDoH is DNS-over-HTTPS.
	ProtoDoH Protocol = 3

	// ProtoDoQ is DNS-over-QUIC.
	ProtoDoQ Protocol = 4

	// ProtoDoT is DNS-over-TLS.
	ProtoDoT Protocol = 5

	// ProtoDNSCrypt is DNSCrypt.
	ProtoDNSCrypt Protocol = 9
)

// String implements the fmt.Stringer interface for Protocol.
func (p Protocol) String() (s string) {
	switch p {
	case ProtoDNS:
		return "dns"
	case ProtoDoH:
		return "doh"
	case ProtoDoQ:
		return "doq"
	case ProtoDoT:
		return "dot"
	case ProtoDNSCrypt:
		return "dnscrypt"
	default:
		return fmt.Sprintf("!bad_protocol_%d", p)
	}
}

// ALPN returns the application-layer negotiation strings for p.  For protocols
// with no ALPN it returns nil.
func (p Protocol) ALPN() (alpn []string) {
	switch p {
	case ProtoDoT:
		return []string{"dot"}
	case ProtoDoQ:
		return []string{nextProtoDoQ}
	case ProtoDoH:
		return slices.Clone(nextProtoDoH3)
	default:
		return nil
	}
}

// HasPaddingSupport returns true if the protocol supports EDNS0 padding.  For
// DoQ and DoH3 the padding should be added with QUIC, but as long as we can't
// control it yet, we add DoQ protocol here.
// TODO(d.kolyshev): Remove DoQ from this list.
func (p Protocol) HasPaddingSupport() (ok bool) {
	return p.IsStdEncrypted()
}

// IsStdEncrypted returns true if the protocol is one of the standard encrypted
// DNS protocol as defined by an RFC.
func (p Protocol) IsStdEncrypted() (ok bool) {
	return p == ProtoDoT || p == ProtoDoH || p == ProtoDoQ
}

// Network is a enum with net protocols TCP and UDP.
// Used for a kind of validation.
type Network string

// Network enum members.  Note that we use "tcp" and "udp" strings so that
// we could use these constants when calling golang net package functions.
const (
	NetworkTCP Network = "tcp"
	NetworkUDP Network = "udp"
	NetworkAny Network = ""
)

// CanTCP returns true if this Network supports TCP.
func (n Network) CanTCP() (ok bool) {
	return n == NetworkAny || n == NetworkTCP
}

// CanUDP returns true if this Network supports UDP.
func (n Network) CanUDP() (ok bool) {
	return n == NetworkAny || n == NetworkUDP
}

// NetworkFromAddr returns NetworkTCP or NetworkUDP depending on the address.
func NetworkFromAddr(addr net.Addr) (network Network) {
	switch addr.Network() {
	case "udp":
		return NetworkUDP
	case "tcp":
		return NetworkTCP
	default:
		panic(fmt.Sprintf("unexpected network type %s", addr.Network()))
	}
}

const (
	// DNSHeaderSize is the DNS query header size.
	DNSHeaderSize = 12
)
