// Package devicefinder contains the default implementation of the
// [agd.DeviceFinder] interface.
package devicefinder

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/miekg/dns"
)

// Config is the configuration structure for the default device finder.
type Config struct {
	// HumanIDParser is used to normalize and parse human-readable device
	// identifiers.  It must not be nil.
	HumanIDParser *agd.HumanIDParser

	// Logger is used to log the operation of the device finder.  It must not be
	// nil.
	Logger *slog.Logger

	// Server contains the data of the server for which the profiles are found.
	// It must not be nil.
	Server *agd.Server

	// CustomDomainDB is used to match custom domains.  It must not be nil.
	CustomDomainDB CustomDomainDB

	// Metrics are used to collect the statistics of the default device finder.
	// It must not be nil.
	Metrics Metrics

	// ProfileDB is used to find the profiles.  It must not be nil.
	ProfileDB profiledb.Interface

	// DeviceDomains, if any, provides the domain names to use for looking up
	// device ID from TLS server names.
	DeviceDomains []string
}

// Default is the default device finder.
type Default struct {
	humanIDParser  *agd.HumanIDParser
	logger         *slog.Logger
	srv            *agd.Server
	customDomainDB CustomDomainDB
	metrics        Metrics
	profileDB      profiledb.Interface
	deviceDomains  []string
}

// NewDefault returns a new default device finder.  c must be valid and non-nil.
func NewDefault(c *Config) (f *Default) {
	return &Default{
		humanIDParser:  c.HumanIDParser,
		logger:         c.Logger,
		srv:            c.Server,
		customDomainDB: c.CustomDomainDB,
		metrics:        c.Metrics,
		profileDB:      c.ProfileDB,
		deviceDomains:  c.DeviceDomains,
	}
}

// type check
var _ agd.DeviceFinder = (*Default)(nil)

// Find implements the [agd.DeviceFinder] interface for *Default.  ctx must
// contain [*dnsserver.RequestInfo].
func (f *Default) Find(
	ctx context.Context,
	req *dns.Msg,
	raddr netip.AddrPort,
	laddr netip.AddrPort,
) (r agd.DeviceResult) {
	if !supportsDeviceID(f.srv.Protocol) {
		return nil
	}

	srvReqInfo := dnsserver.MustRequestInfoFromContext(ctx)
	dd, err := f.deviceData(ctx, req, srvReqInfo)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return &agd.DeviceResultError{
			Err: err,
		}
	}

	r = f.findDevice(ctx, laddr, raddr.Addr(), dd)
	if r, ok := r.(*agd.DeviceResultOK); ok {
		return f.authenticatedResult(ctx, srvReqInfo, r)
	}

	return r
}

// supportsDeviceID returns true if p supports a way to get a device ID.
func supportsDeviceID(p agd.Protocol) (ok bool) {
	switch p {
	case
		agd.ProtoDNS,
		agd.ProtoDoH,
		agd.ProtoDoQ,
		agd.ProtoDoT:
		return true
	default:
		return false
	}
}
