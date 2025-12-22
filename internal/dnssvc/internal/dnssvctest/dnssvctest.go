// Package dnssvctest contains common constants and utilities for the internal
// DNS-service packages.
package dnssvctest

import (
	"crypto/tls"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/miekg/dns"
)

// Timeout is the common timeout for tests.
const Timeout time.Duration = 1 * time.Second

// Common IDs for tests and their string representations.
const (
	DeviceIDStr     = "dev1234"
	ProfileIDStr    = "prof1234"
	HumanIDStr      = "My-Device-X--10"
	HumanIDLowerStr = "my-device-x--10"

	DeviceID     agd.DeviceID     = DeviceIDStr
	ProfileID    agd.ProfileID    = ProfileIDStr
	HumanID      agd.HumanID      = HumanIDStr
	HumanIDLower agd.HumanIDLower = HumanIDLowerStr
)

// String representations for the common filtering-rule list ID for tests.
const (
	FilterListID1Str = "flt_1"
	FilterListID2Str = "flt_2"
)

// Common filtering-rule list ID for tests.
const (
	FilterListID1 filter.ID = FilterListID1Str
	FilterListID2 filter.ID = FilterListID2Str
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

const (
	// FilteringGroupID is the common filtering-group ID for tests.
	FilteringGroupID agd.FilteringGroupID = "test_filtering_group"

	// ServerName is the common server name for tests.
	ServerName agd.ServerName = "test_server_dns_tls"

	// ServerGroupName is the common server-group name for tests.
	ServerGroupName agd.ServerGroupName = "test_server_group"
)

const (
	// DomainForDevices is the upper-level domain name for requests with device
	// in e.g. HTTP path.
	DomainForDevices = "d.dns.example"

	// DeviceIDSrvName is the common client server-name with a device ID for
	// tests.
	DeviceIDSrvName = DeviceIDStr + "." + DomainForDevices

	// HumanIDPath is the common client URL path with human-readable device-data
	// for tests.
	HumanIDPath = "otr-" + ProfileIDStr + "-" + HumanIDStr

	// HumanIDSrvName is the common client server-name with human-readable
	// device-data for tests.
	HumanIDSrvName = HumanIDPath + "." + DomainForDevices
)

// Use a constant block with iota to keep track of the unique final bytes of IP
// addresses more easily.
const (
	ipByteZero = iota
	ipByteClient
	ipByteServer
	ipByteDomain
	ipByteLinked
	ipByteDedicated
)

// Common addresses for tests.
var (
	ClientIP      = net.IP{192, 0, 2, ipByteClient}
	ClientTCPAddr = &net.TCPAddr{
		IP:   ClientIP,
		Port: 12345,
	}

	ClientAddrPort = ClientTCPAddr.AddrPort()
	ClientAddr     = ClientAddrPort.Addr()

	ServerTCPAddr = &net.TCPAddr{
		IP:   net.IP{192, 0, 2, ipByteServer},
		Port: 54321,
	}

	ServerAddrPort = ServerTCPAddr.AddrPort()
	ServerAddr     = ServerAddrPort.Addr()

	DomainAddrIPv4 = netip.AddrFrom4([4]byte{192, 0, 2, ipByteDomain})
	DomainAddrIPv6 = netip.AddrFrom16([16]byte{
		0x20, 0x01, 0x0d, 0xb8,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, ipByteDomain,
	})

	LinkedAddr     = netip.AddrFrom4([4]byte{192, 0, 2, ipByteLinked})
	LinkedAddrPort = netip.AddrPortFrom(LinkedAddr, 12345)

	DedicatedAddr     = netip.AddrFrom4([4]byte{192, 0, 2, ipByteDedicated})
	DedicatedAddrPort = netip.AddrPortFrom(DedicatedAddr, 53)
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
		srv.TLS = &agd.TLSConfig{
			Default: &tls.Config{},
		}
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

// NewRequestInfo returns a new *dnsserver.RequestInfo for tests.
func NewRequestInfo(tlsSrvName string) (ri *dnsserver.RequestInfo) {
	return &dnsserver.RequestInfo{
		TLS: &tls.ConnectionState{
			ServerName: tlsSrvName,
		},
		StartTime: time.Now(),
	}
}
