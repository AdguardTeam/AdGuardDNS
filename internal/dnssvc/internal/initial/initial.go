// Package initial contains the initial, outermost (except for ratelimit)
// middleware of the AdGuard DNS server.  It filters out the Firefox canary
// domain logic, sets and resets the AD bit for further processing, as well as
// puts as much information as it can into the context and request info.
package initial

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdsync"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Middleware is the initial middleware of the AdGuard DNS server.  This
// middleware must be the most outer middleware apart from the ratelimit one.
type Middleware struct {
	// messages is used to build the responses specific for the request's
	// context.
	messages *dnsmsg.Constructor

	// fltGrp is the filtering group to which srv belongs.
	fltGrp *agd.FilteringGroup

	// srvGrp is the server group to which srv belongs.
	srvGrp *agd.ServerGroup

	// srv is the current server which serves the request.
	srv *agd.Server

	// pool is the pool of [agd.RequestInfo] values.
	pool *agdsync.TypedPool[agd.RequestInfo]

	// db is the database of user profiles and devices.
	db profiledb.Interface

	// geoIP detects the location of the request source.
	geoIP geoip.Interface

	// errColl collects and reports the errors considered non-critical.
	errColl agd.ErrorCollector
}

// Config is the configuration structure for the initial middleware.  All fields
// must be non-nil.
type Config struct {
	// messages is used to build the responses specific for a request's context.
	Messages *dnsmsg.Constructor

	// FilteringGroup is the filtering group to which Server belongs.
	FilteringGroup *agd.FilteringGroup

	// ServerGroup is the server group to which Server belongs.
	ServerGroup *agd.ServerGroup

	// Server is the current server which serves the request.
	Server *agd.Server

	// DB is the database of user profiles and devices.
	ProfileDB profiledb.Interface

	// GeoIP detects the location of the request source.
	GeoIP geoip.Interface

	// ErrColl collects and reports the errors considered non-critical.
	ErrColl agd.ErrorCollector
}

// New returns a new initial middleware.  c must not be nil.
func New(c *Config) (mw *Middleware) {
	return &Middleware{
		messages: c.Messages,
		fltGrp:   c.FilteringGroup,
		srvGrp:   c.ServerGroup,
		srv:      c.Server,
		pool: agdsync.NewTypedPool(func() (v *agd.RequestInfo) {
			return &agd.RequestInfo{}
		}),
		db:      c.ProfileDB,
		geoIP:   c.GeoIP,
		errColl: c.ErrColl,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *Middleware
func (mw *Middleware) Wrap(next dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "init mw: %w") }()

		// Save the actual value of the request AD and DO bits and set the AD
		// bit in the request to true, so that the upstream validates the data
		// and caches the actual value of the response AD bit.  Restore it
		// later, depending on the request and response data.
		reqAD := req.AuthenticatedData
		reqDO := dnsmsg.IsDO(req)
		req.AuthenticatedData = true

		// Assume that module dnsserver has already validated that the request
		// always has exactly one question for us.
		q := req.Question[0]
		qt := q.Qtype
		cl := q.Qclass

		// Get the request's information, such as GeoIP data and user profiles.
		ri, err := mw.newRequestInfo(ctx, req, rw.LocalAddr(), rw.RemoteAddr(), q.Name, qt, cl)
		if err != nil {
			// Don't wrap the error, because this is the main flow, and there is
			// already [errors.Annotate] here.
			return mw.processReqInfoErr(ctx, rw, req, err)
		}
		defer mw.pool.Put(ri)

		if specHdlr, name := mw.reqInfoSpecialHandler(ri, cl); specHdlr != nil {
			optlog.Debug1("init mw: got req-info special handler %s", name)

			// Don't wrap the error, because it's informative enough as is, and
			// because if handled is true, the main flow terminates here.
			return specHdlr(ctx, rw, req, ri)
		}

		ctx = agd.ContextWithRequestInfo(ctx, ri)

		// Record the response, restore the AD bit value in both the request and
		// the response, and write the response.
		nwrw := internal.MakeNonWriter(rw)
		err = next.ServeDNS(ctx, nwrw, req)
		if err != nil {
			// Don't wrap the error, because this is the main flow, and there is
			// already errors.Annotate here.
			return err
		}

		resp := nwrw.Msg()

		// Following RFC 6840, set the AD bit in the response only when the
		// response is authenticated, and the request contained either a set DO
		// bit or a set AD bit.
		//
		// See https://datatracker.ietf.org/doc/html/rfc6840#section-5.8.
		resp.AuthenticatedData = resp.AuthenticatedData && (reqAD || reqDO)

		err = rw.WriteMsg(ctx, req, resp)

		return errors.Annotate(err, "writing resp: %w")
	}

	return dnsserver.HandlerFunc(f)
}

// newRequestInfo returns the new request information structure using the
// middleware's configuration and values from ctx.
func (mw *Middleware) newRequestInfo(
	ctx context.Context,
	req *dns.Msg,
	laddr net.Addr,
	raddr net.Addr,
	fqdn string,
	qt dnsmsg.RRType,
	cl dnsmsg.Class,
) (ri *agd.RequestInfo, err error) {
	ri = mw.pool.Get()

	// Use ri as an argument here to evaluate and save the non-nil value of ri
	// and prevent returns with an error from overwriting ri with nil.
	defer func(fromPool *agd.RequestInfo) {
		if err != nil {
			mw.pool.Put(fromPool)
		}
	}(ri)

	// Clear all fields that must be set later.
	ri.Device = nil
	ri.Profile = nil
	ri.ECS = nil
	ri.Location = nil

	// Put the host, server, and client IP data into the request information
	// immediately.
	ri.FilteringGroup = mw.fltGrp
	ri.Messages = mw.messages
	ri.RemoteIP = netutil.NetAddrToAddrPort(raddr).Addr()
	ri.ServerGroup = mw.srvGrp.Name
	ri.Server = mw.srv.Name
	ri.Host = agdnet.NormalizeDomain(fqdn)
	ri.QType = qt
	ri.QClass = cl

	// As an optimization, put the request ID closer to the top of the context
	// stack.
	ri.ID, _ = agd.RequestIDFromContext(ctx)

	// Add the GeoIP information, if any.
	err = mw.addLocation(ctx, ri, req)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	// Add the profile information, if any.
	localIP := netutil.NetAddrToAddrPort(laddr).Addr()
	err = mw.addProfile(ctx, ri, req, localIP)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return ri, nil
}

// addLocation adds GeoIP location information about the client's remote address
// as well as the EDNS Client Subnet information, if there is one, to ri.  err
// is not nil only if req contains a malformed EDNS Client Subnet option.
func (mw *Middleware) addLocation(ctx context.Context, ri *agd.RequestInfo, req *dns.Msg) (err error) {
	ri.Location = mw.locationData(ctx, ri.RemoteIP, "client")

	ecs, scope, err := dnsmsg.ECSFromMsg(req)
	if err != nil {
		return fmt.Errorf("adding ecs info: %w", err)
	} else if ecs != (netip.Prefix{}) {
		ri.ECS = &agd.ECS{
			Location: mw.locationData(ctx, ecs.Addr(), "ecs"),
			Subnet:   ecs,
			Scope:    scope,
		}
	}

	return nil
}

// locationData returns the GeoIP location information about the IP address.
// typ is the type of data being requested for error reporting and logging.
func (mw *Middleware) locationData(ctx context.Context, ip netip.Addr, typ string) (l *agd.Location) {
	l, err := mw.geoIP.Data("", ip)
	if err != nil {
		// Consider GeoIP errors non-critical.  Report and go on.
		agd.Collectf(ctx, mw.errColl, "init mw: getting geoip for %s ip: %w", typ, err)
	}

	if l == nil {
		optlog.Debug2("init mw: no geoip for %s ip %s", typ, ip)
	} else {
		optlog.Debug4("init mw: found country/asn %q/%d for %s ip %s", l.Country, l.ASN, typ, ip)
	}

	return l
}

// processReqInfoErr processes the error returned by [Middleware.newRequestInfo]
// and returns the properly handled and/or wrapped error.
func (mw *Middleware) processReqInfoErr(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	origErr error,
) (err error) {
	var ecsErr dnsmsg.BadECSError
	if errors.As(origErr, &ecsErr) {
		// We've got a bad ECS option.  Log and respond with a FORMERR
		// immediately.
		optlog.Debug1("init mw: %s", origErr)

		writeErr := rw.WriteMsg(ctx, req, mw.messages.NewMsgFORMERR(req))
		writeErr = errors.Annotate(writeErr, "writing formerr resp: %w")

		return errors.WithDeferred(origErr, writeErr)
	}

	return origErr
}
