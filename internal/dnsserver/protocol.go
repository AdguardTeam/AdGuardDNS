package dnsserver

import (
	"fmt"

	"golang.org/x/exp/slices"
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

	// ProtoDNSTCP is plain DNS over TCP.
	ProtoDNSTCP Protocol = 1

	// ProtoDNSUDP is plain DNS over UDP.
	ProtoDNSUDP Protocol = 2

	// ProtoDoH is DNS-over-HTTPS.
	ProtoDoH Protocol = 3

	// ProtoDoQ is DNS-over-QUIC.
	ProtoDoQ Protocol = 4

	// ProtoDoT is DNS-over-TLS.
	ProtoDoT Protocol = 5

	// ProtoDNSCryptTCP is DNSCrypt over TCP.
	ProtoDNSCryptTCP Protocol = 6

	// ProtoDNSCryptUDP is DNSCrypt over UDP.
	ProtoDNSCryptUDP Protocol = 7
)

// String implements the fmt.Stringer interface for Protocol.
func (p Protocol) String() (s string) {
	switch p {
	case ProtoDNSTCP:
		return "dns-tcp"
	case ProtoDNSUDP:
		return "dns-udp"
	case ProtoDoH:
		return "doh"
	case ProtoDoQ:
		return "doq"
	case ProtoDoT:
		return "dot"
	case ProtoDNSCryptTCP:
		return "dnscrypt-tcp"
	case ProtoDNSCryptUDP:
		return "dnscrypt-udp"
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
		return slices.Clone(nextProtoDoH)
	default:
		return nil
	}
}

// IsStdEncrypted returns true if the protocol is one of the standard encrypted
// DNS protocol as defined by an RFC.
func (p Protocol) IsStdEncrypted() (ok bool) {
	return p == ProtoDoH || p == ProtoDoT || p == ProtoDoQ
}

// Network is a enum with net protocols TCP and UDP.
// Used for a kind of validation.
type Network string

// Network enum members. Note that we use "tcp" and "udp" strings so that
// we could use these constants when calling golang net package functions.
const (
	NetworkTCP Network = "tcp"
	NetworkUDP Network = "udp"
)

const (
	// DNSHeaderSize is the DNS query header size.
	DNSHeaderSize = 12
)
