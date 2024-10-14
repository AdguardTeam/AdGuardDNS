package ratelimitmw

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// newRequestInfo returns the new request information structure using the
// middleware's configuration and values from ctx.  ri is never nil and should
// be returned to the pool.
func (mw *Middleware) newRequestInfo(
	ctx context.Context,
	req *dns.Msg,
	laddr net.Addr,
	raddr netip.AddrPort,
) (ri *agd.RequestInfo) {
	ri = mw.pool.Get()

	// Clear all fields that must be set later.
	ri.DeviceResult = nil
	ri.ECS = nil
	ri.Location = nil

	// Put the host, server, and client IP data into the request information
	// immediately.
	ri.Messages = mw.messages
	ri.RemoteIP = raddr.Addr()

	// Assume that module dnsserver has already validated that the request
	// always has exactly one question for us.
	q := req.Question[0]
	ri.Host = agdnet.NormalizeDomain(q.Name)
	ri.QType = q.Qtype
	ri.QClass = q.Qclass

	// As an optimization, put the request ID closer to the top of the context
	// stack.
	ri.ID, _ = agd.RequestIDFromContext(ctx)

	// Add the profile information, if any.
	localAddr := netutil.NetAddrToAddrPort(laddr)
	ri.DeviceResult = mw.deviceFinder.Find(ctx, req, raddr, localAddr)
	if r, ok := ri.DeviceResult.(*agd.DeviceResultOK); ok {
		p, cloner := r.Profile, mw.messages.Cloner()
		messages, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
			Cloner:              cloner,
			BlockingMode:        p.BlockingMode,
			FilteredResponseTTL: p.FilteredResponseTTL,
		})
		if err != nil {
			err = fmt.Errorf("creating constructor for profile %q: %w", p.ID, err)
			errcoll.Collect(ctx, mw.errColl, mw.logger, "ratelimit", err)
		} else {
			ri.Messages = messages
		}
	}

	return ri
}

// location returns the GeoIP location information about the client's remote
// address as well as the EDNS Client Subnet information, if there is one.  err
// is not nil only if req contains a malformed EDNS Client Subnet option.
func (mw *Middleware) location(
	ctx context.Context,
	req *dns.Msg,
	remoteIP netip.Addr,
) (loc *geoip.Location, ecs *dnsmsg.ECS, err error) {
	loc = mw.locationData(ctx, remoteIP, "client")

	subnet, scope, err := dnsmsg.ECSFromMsg(req)
	if err != nil {
		return loc, nil, fmt.Errorf("getting ecs info: %w", err)
	} else if subnet != (netip.Prefix{}) {
		ecs = &dnsmsg.ECS{
			Location: mw.locationData(ctx, subnet.Addr(), "ecs"),
			Subnet:   subnet,
			Scope:    scope,
		}
	}

	return loc, ecs, nil
}

// locationData returns the GeoIP location information about the IP address.
// typ is the type of data being requested for error reporting and logging.
func (mw *Middleware) locationData(
	ctx context.Context,
	ip netip.Addr,
	typ string,
) (l *geoip.Location) {
	l, err := mw.geoIP.Data("", ip)
	if err != nil {
		// Consider GeoIP errors non-critical.  Report and go on.
		err = fmt.Errorf("getting data for %s ip: %w", typ, err)
		errcoll.Collect(ctx, mw.errColl, mw.logger, "ratelimit geoip", err)
	}

	if l == nil {
		optslog.Trace2(ctx, mw.logger, "no location", "type", typ, "ip", ip)
	} else {
		optslog.Trace3(ctx, mw.logger, "found location", "location", l, "type", typ, "ip", ip)
	}

	return l
}
