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
	// Logger is used to log the operation of the device finder.  It must not be
	// nil.
	Logger *slog.Logger

	// ProfileDB is used to find the profiles.  It must not be nil.
	ProfileDB profiledb.Interface

	// HumanIDParser is used to normalize and parse human-readable device
	// identifiers.  It must not be nil.
	HumanIDParser *agd.HumanIDParser

	// Server contains the data of the server for which the profiles are found.
	// It must not be nil.
	Server *agd.Server

	// DeviceDomains, if any, provides the domain names to use for looking up
	// device ID from TLS server names.
	DeviceDomains []string
}

// Default is the default device finder.
//
// TODO(a.garipov): Use.
type Default struct {
	logger        *slog.Logger
	db            profiledb.Interface
	humanIDParser *agd.HumanIDParser
	srv           *agd.Server
	deviceDomains []string
}

// NewDefault returns a new default device finder.  c must be valid and non-nil.
func NewDefault(c *Config) (f *Default) {
	return &Default{
		logger:        c.Logger,
		db:            c.ProfileDB,
		humanIDParser: c.HumanIDParser,
		srv:           c.Server,
		deviceDomains: c.DeviceDomains,
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
	id, extID, err := f.deviceData(ctx, req, srvReqInfo)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return &agd.DeviceResultError{
			Err: err,
		}
	}

	r = f.findDevice(ctx, laddr, raddr.Addr(), id, extID)
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
