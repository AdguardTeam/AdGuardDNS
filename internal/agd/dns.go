package agd

import "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"

// Common DNS Message Constants, Types, And Utilities

// Protocol is a DNS protocol.  It is reexported here to lower the degree of
// dependency on the dnsserver module.
type Protocol = dnsserver.Protocol

// Protocol value constants.  They are reexported here to lower the degree of
// dependency on the dnsserver module.
const (
	// NOTE: DO NOT change the numerical values or use iota, because other
	// packages and modules may depend on the numerical values.  These numerical
	// values are a part of the API.

	ProtoInvalid  = dnsserver.ProtoInvalid
	ProtoDNS      = dnsserver.ProtoDNS
	ProtoDoH      = dnsserver.ProtoDoH
	ProtoDoQ      = dnsserver.ProtoDoQ
	ProtoDoT      = dnsserver.ProtoDoT
	ProtoDNSCrypt = dnsserver.ProtoDNSCrypt
)
