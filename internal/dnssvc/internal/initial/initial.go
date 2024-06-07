// Package initial contains the initial, outermost (except for ratelimit and
// access) middleware of the AdGuard DNS server.  It handles Firefox canary
// hosts requests, applies profile access restrictions, sets and resets the AD
// bit for further processing, as well as puts as much information as it can
// into the context and request info.
package initial

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicesetter"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// Middleware is the initial middleware of the AdGuard DNS server.  This
// middleware must be the most outer middleware apart from the ratelimit and
// global access middlewares.
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
	pool *syncutil.Pool[agd.RequestInfo]

	// deviceSetter is used to set the device and profile for a request, if any.
	deviceSetter devicesetter.Interface

	// geoIP detects the location of the request source.
	geoIP geoip.Interface

	// errColl collects and reports the errors considered non-critical.
	errColl errcoll.Interface
}

// Config is the configuration structure for the initial middleware.  All fields
// must be non-nil.
type Config struct {
	// Messages is used to build the responses specific for a request's context.
	Messages *dnsmsg.Constructor

	// FilteringGroup is the filtering group to which Server belongs.
	FilteringGroup *agd.FilteringGroup

	// ServerGroup is the server group to which Server belongs.
	ServerGroup *agd.ServerGroup

	// Server is the current server which serves the request.
	Server *agd.Server

	// DeviceSetter is used to set the device and profile for a request, if any.
	DeviceSetter devicesetter.Interface

	// GeoIP detects the location of the request source.
	GeoIP geoip.Interface

	// ErrColl collects and reports the errors considered non-critical.
	ErrColl errcoll.Interface
}

// New returns a new initial middleware.  c must not be nil, and all its fields
// must be valid.
func New(c *Config) (mw *Middleware) {
	return &Middleware{
		messages: c.Messages,
		fltGrp:   c.FilteringGroup,
		srvGrp:   c.ServerGroup,
		srv:      c.Server,
		pool: syncutil.NewPool(func() (v *agd.RequestInfo) {
			return &agd.RequestInfo{}
		}),
		deviceSetter: c.DeviceSetter,
		geoIP:        c.GeoIP,
		errColl:      c.ErrColl,
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

		rAddr := netutil.NetAddrToAddrPort(rw.RemoteAddr())

		// Get the request's information, such as GeoIP data and user profiles.
		ri, err := mw.newRequestInfo(ctx, req, rw.LocalAddr(), rAddr)
		if err != nil {
			// Don't wrap the error, because this is the main flow, and there is
			// already [errors.Annotate] here.
			return mw.processReqInfoErr(ctx, rw, req, err)
		}
		defer mw.pool.Put(ri)

		// Apply profile access restrictions.
		if isBlockedByProfileAccess(ri, req, rAddr) {
			optlog.Debug1("init mw: access: profile: req %q blocked", ri.ID)
			metrics.AccessBlockedForProfileTotal.Inc()

			return nil
		}

		if specHdlr, name := mw.reqInfoSpecialHandler(ri); specHdlr != nil {
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
	raddr netip.AddrPort,
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
	remoteIP := raddr.Addr()
	ri.FilteringGroup = mw.fltGrp
	ri.Messages = mw.messages
	ri.RemoteIP = remoteIP
	ri.ServerGroup = mw.srvGrp.Name
	ri.Server = mw.srv.Name
	ri.Proto = mw.srv.Protocol

	// Assume that module dnsserver has already validated that the request
	// always has exactly one question for us.
	q := req.Question[0]
	ri.Host = agdnet.NormalizeDomain(q.Name)
	ri.QType = q.Qtype
	ri.QClass = q.Qclass

	// As an optimization, put the request ID closer to the top of the context
	// stack.
	ri.ID, _ = agd.RequestIDFromContext(ctx)

	// Add the GeoIP information, if any.
	err = mw.addLocation(ctx, req, ri)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	// Add the profile information, if any.
	localAddr := netutil.NetAddrToAddrPort(laddr)
	err = mw.deviceSetter.SetDevice(ctx, req, ri, localAddr)
	if err != nil {
		return nil, fmt.Errorf("getting device from req: %w", err)
	}

	return ri, nil
}

// processReqInfoErr processes the error returned by [Middleware.newRequestInfo]
// and returns the properly handled and/or wrapped error.
func (mw *Middleware) processReqInfoErr(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	origErr error,
) (err error) {
	if errors.Is(origErr, devicesetter.ErrUnknownDedicated) {
		metrics.DNSSvcUnknownDedicatedTotal.Inc()

		// The request is dropped by the profile search.  Don't write anything
		// and just return.
		return nil
	}

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

// isBlockedByProfileAccess returns true if req is blocked by profile access
// settings.
func isBlockedByProfileAccess(
	ri *agd.RequestInfo,
	req *dns.Msg,
	rAddr netip.AddrPort,
) (blocked bool) {
	return ri.Profile != nil &&
		ri.Profile.Access.IsBlocked(req, rAddr, ri.Location)
}
