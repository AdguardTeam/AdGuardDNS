// Package ratelimitmw contains the access and ratelimiting middleware of the
// AdGuard DNS server.
//
// TODO(a.garipov):  Imp tests.
package ratelimitmw

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Middleware is the access and ratelimiting middleware of the AdGuard DNS
// server.  Since AdGuard DNS allows users to set their own access and
// ratelimiting rules, it also finds the profile data and adds [agd.RequestInfo]
// to the context.
type Middleware struct {
	logger        *slog.Logger
	messages      *dnsmsg.Constructor
	pool          *syncutil.Pool[agd.RequestInfo]
	sdeConf       *dnsmsg.StructuredDNSErrorsConfig
	accessManager access.Interface
	deviceFinder  agd.DeviceFinder
	errColl       errcoll.Interface
	geoIP         geoip.Interface
	limiter       ratelimit.Interface
	metrics       Metrics
	protos        []dnsserver.Protocol
	edeEnabled    bool
}

// Config is the configuration structure for the access and ratelimiting
// middleware.  All fields must not be empty.
type Config struct {
	// Logger is used to log the operation of the middleware.
	Logger *slog.Logger

	// Messages is used to build the responses specific for a request's context.
	Messages *dnsmsg.Constructor

	// FilteringGroup is the filtering group to which [Config.Server] belongs.
	FilteringGroup *agd.FilteringGroup

	// ServerGroup is the server group to which [Config.Server] belongs.
	ServerGroup *agd.ServerGroup

	// Server is the current server which serves the request.
	Server *agd.Server

	// StructuredErrors is the configuration for the experimental Structured DNS
	// Errors feature for the profiles' message constructors.
	StructuredErrors *dnsmsg.StructuredDNSErrorsConfig

	// AccessManager is the global access manager.
	AccessManager access.Interface

	// DeviceFinder is used to set the device and profile for a request, if any.
	DeviceFinder agd.DeviceFinder

	// ErrColl collects and reports the errors considered non-critical.
	ErrColl errcoll.Interface

	// GeoIP detects the location of the request source.
	GeoIP geoip.Interface

	// Metrics is a listener for the middleware events.
	Metrics Metrics

	// Limiter defines whether the query should be dropped or not.
	Limiter ratelimit.Interface

	// Protocols is a list of protocols this middleware applies ratelimiting
	// logic to.  Protocols must not be changed after calling [New].
	Protocols []agd.Protocol

	// EDEEnabled enables the addition of the Extended DNS Error (EDE) codes in
	// the profiles' message constructors.
	EDEEnabled bool
}

// New returns a new access middleware.  c must not be nil.
func New(c *Config) (mw *Middleware) {
	return &Middleware{
		logger:   c.Logger,
		messages: c.Messages,
		pool: syncutil.NewPool(func() (v *agd.RequestInfo) {
			// Set the filtering-group and server information here immediately.
			return &agd.RequestInfo{
				FilteringGroup: c.FilteringGroup,
				ServerGroup:    c.ServerGroup,
				Server:         c.Server.Name,
				Proto:          c.Server.Protocol,
			}
		}),
		sdeConf:       c.StructuredErrors,
		accessManager: c.AccessManager,
		deviceFinder:  c.DeviceFinder,
		errColl:       c.ErrColl,
		geoIP:         c.GeoIP,
		limiter:       c.Limiter,
		metrics:       c.Metrics,
		protos:        c.Protocols,
		edeEnabled:    c.EDEEnabled,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *Middleware
func (mw *Middleware) Wrap(next dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "ratelimit mw: %w") }()

		raddr := netutil.NetAddrToAddrPort(rw.RemoteAddr())
		if raddr.Port() == 0 {
			// Probably spoofing.  Return immediately.
			mw.metrics.OnRateLimited(ctx, req, rw)

			return nil
		}

		remoteIP := raddr.Addr()
		loc, ecs, err := mw.location(ctx, req, remoteIP)
		if err != nil {
			return mw.processLocationErr(ctx, rw, req, err)
		}

		ri := mw.newRequestInfo(ctx, req, rw.LocalAddr(), raddr)
		defer mw.pool.Put(ri)

		cont, err := mw.handleDeviceResult(ctx, ri.DeviceResult)
		if !cont {
			// Don't wrap the error, because this is the main flow, and there is
			// already [errors.Annotate] here.
			return err
		}

		ri.Location, ri.ECS = loc, ecs

		if mw.isBlockedByAccess(ctx, ri, req, raddr) {
			return nil
		}

		ctx = agd.ContextWithRequestInfo(ctx, ri)

		// Don't wrap the error, because this is the main flow, and there is
		// [errors.Annotate].
		return mw.serveWithRatelimiting(ctx, rw, req, ri, next)
	}

	return dnsserver.HandlerFunc(f)
}

// processLocationErr processes the error returned by [Middleware.location] and
// returns the properly handled and/or wrapped error.
func (mw *Middleware) processLocationErr(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	origErr error,
) (err error) {
	var ecsErr dnsmsg.BadECSError
	if !errors.As(origErr, &ecsErr) {
		return origErr
	}

	// We've got a bad ECS option.  Log and respond with a FORMERR immediately.
	optslog.Debug1(ctx, mw.logger, "ecs error", slogutil.KeyError, origErr)

	resp := mw.messages.NewRespRCode(req, dns.RcodeFormatError)
	writeErr := rw.WriteMsg(ctx, req, resp)
	writeErr = errors.Annotate(writeErr, "writing formerr resp: %w")

	return errors.WithDeferred(origErr, writeErr)
}

// handleDeviceResult processes the device result and indicates whether the
// handler should proceed and the error to return if not.
func (mw *Middleware) handleDeviceResult(
	ctx context.Context,
	res agd.DeviceResult,
) (cont bool, err error) {
	switch res := res.(type) {
	case *agd.DeviceResultUnknownDedicated:
		mw.metrics.IncrementUnknownDedicated(ctx)

		// The request is dropped by the profile search.  Don't write anything
		// and just return.
		return false, nil
	case *agd.DeviceResultError:
		return false, res.Err
	}

	return true, nil
}
