// Package dnssvctest contains common constants and utilities for the internal
// DNS-service packages.
package dnssvctest

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/miekg/dns"
)

// Timeout is the common timeout for tests.
const Timeout time.Duration = 1 * time.Second

// String representations of the common IDs for tests.
const (
	DeviceIDStr  = "dev1234"
	ProfileIDStr = "prof1234"
)

// DeviceID is the common device ID for tests.
const DeviceID agd.DeviceID = DeviceIDStr

// ProfileID is the common profile ID for tests.
const ProfileID agd.ProfileID = ProfileIDStr

// String representations for the common filtering-rule list ID for tests.
const (
	FilterListID1Str = "flt_1"
	FilterListID2Str = "flt_2"
)

// Common filtering-rule list ID for tests.
const (
	FilterListID1 agd.FilterListID = FilterListID1Str
	FilterListID2 agd.FilterListID = FilterListID2Str
)

// Common domains and FQDNs for tests.
const (
	Domain               = "test.example"
	DomainAllowed        = "allowed.example"
	DomainBlocked        = "blocked.example"
	DomainRewritten      = "rewritten.example"
	DomainRewrittenCNAME = "rewritten-cname.example"

	DomainFQDN               = Domain + "."
	DomainAllowedFQDN        = DomainAllowed + "."
	DomainBlockedFQDN        = DomainBlocked + "."
	DomainRewrittenFQDN      = DomainRewritten + "."
	DomainRewrittenCNAMEFQDN = DomainRewrittenCNAME + "."
)

// ServerName is the common server name for tests.
const ServerName agd.ServerName = "test_server_dns_tls"

// DeviceIDWildcard is the common wildcard domain for retrieving [agd.DeviceID]
// in tests.  Use [strings.ReplaceAll] to replace the "*" symbol with the actual
// [agd.DeviceID].
const DeviceIDWildcard = "*.dns.example.com"

// Common addresses for tests.
var (
	ClientIP   = net.IP{1, 2, 3, 4}
	RemoteAddr = &net.TCPAddr{
		IP:   ClientIP,
		Port: 12345,
	}

	ClientAddrPort = RemoteAddr.AddrPort()
	ClientAddr     = ClientAddrPort.Addr()

	LocalAddr = &net.TCPAddr{
		IP:   net.IP{5, 6, 7, 8},
		Port: 54321,
	}

	ServerAddrPort = LocalAddr.AddrPort()
	ServerAddr     = ServerAddrPort.Addr()
)

// NewServer is a helper that returns a new *agd.Server for tests.
func NewServer(
	name agd.ServerName,
	proto agd.Protocol,
	bindData ...*agd.ServerBindData,
) (srv *agd.Server) {
	srv = &agd.Server{
		Name:         name,
		Protocol:     proto,
		ReadTimeout:  Timeout,
		WriteTimeout: Timeout,
	}

	if proto.IsStdEncrypted() {
		// #nosec G402 -- This is a test helper.
		srv.TLS = &tls.Config{}
	}

	switch proto {
	case agd.ProtoDoH, agd.ProtoDoQ:
		srv.QUICConf = &agd.QUICConfig{}
	case agd.ProtoDNS, agd.ProtoDoT:
		srv.TCPConf = &agd.TCPConfig{
			IdleTimeout: Timeout,
		}

		srv.UDPConf = &agd.UDPConfig{
			MaxRespSize: dns.MaxMsgSize,
		}
	case agd.ProtoDNSCrypt:
		srv.DNSCrypt = &agd.DNSCryptConfig{}
	}

	srv.SetBindData(bindData)

	return srv
}
