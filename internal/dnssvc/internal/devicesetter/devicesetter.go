// Package devicesetter contains the logic for looking up and authenticating
// profiles and devices for a DNS query.
//
// TODO(a.garipov): Use.
package devicesetter

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/miekg/dns"
)

// Interface is the profile-setter interface.
type Interface interface {
	// SetDevice sets the device, profile, and message-constructor data in ri if
	// it can recognize those.  All arguments must not be nil.  ri.RemoteIP must
	// be set.
	//
	// If the request uses a dedicated server IP address for which there are no
	// devices, SetDevice returns [ErrUnknownDedicated].
	//
	// TODO(a.garipov): Consider returning a struct instead of setting things
	// directly in ri.
	SetDevice(
		ctx context.Context,
		req *dns.Msg,
		ri *agd.RequestInfo,
		laddr netip.AddrPort,
	) (err error)
}

// Empty is an [Interface] implementation that does nothing.
type Empty struct{}

// type check
var _ Interface = Empty{}

// SetDevice implements the [Interface] interface for Empty.  It does nothing
// and returns nil.
func (Empty) SetDevice(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
	laddr netip.AddrPort,
) (err error) {
	return nil
}

// Config is the configuration structure for the default profile setter.
type Config struct {
	// ProfileDB is used to find the profiles.  It must not be nil.
	ProfileDB profiledb.Interface

	// Server contains the data of the server for which the profiles are found.
	// It must not be nil.
	Server *agd.Server

	// DeviceIDWildcards, if any, provides the wildcards of domain names to use
	// for looking up device ID from TLS server names.
	DeviceIDWildcards []string
}

// Default is the default profile setter.
type Default struct {
	db              profiledb.Interface
	srv             *agd.Server
	wildcardDomains []string
}

// NewDefault returns a new default profile setter.  c must be non-nil and
// valid.
func NewDefault(c *Config) (ds *Default) {
	var wildcardDomains []string
	for _, w := range c.DeviceIDWildcards {
		wildcardDomains = append(wildcardDomains, strings.TrimPrefix(w, "*."))
	}

	return &Default{
		db:              c.ProfileDB,
		srv:             c.Server,
		wildcardDomains: wildcardDomains,
	}
}

// type check
var _ Interface = (*Default)(nil)

// SetDevice sets the profile, device, and message constructor in ri using the
// information from req and laddr.  ctx must contain [*dnsserver.RequestInfo].
func (ds *Default) SetDevice(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
	laddr netip.AddrPort,
) (err error) {
	if !supportsDeviceID(ds.srv.Protocol) {
		return nil
	}

	srvReqInfo := dnsserver.MustRequestInfoFromContext(ctx)
	id, err := ds.deviceID(req, srvReqInfo)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	prof, dev, err := ds.findDevice(ctx, laddr, ri.RemoteIP, id)
	if err != nil {
		// Likely [errUnknownDedicated].
		return fmt.Errorf("setting profile: %w", err)
	} else if prof == nil || dev == nil {
		return nil
	}

	ds.setDevice(ctx, ri, srvReqInfo, prof, dev)

	return nil
}
