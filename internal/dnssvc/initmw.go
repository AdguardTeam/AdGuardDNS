package dnssvc

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// The Initial Middleware

// initMw is the outermost middleware of the AdGuard DNS server.  It filters out
// the Firefox canary domain logic, sets and resets the AD bit for further
// processing, as well as puts as much information as it can into the context.
//
// This middleware must be the most outer middleware apart from the ratelimit
// one.
//
// TODO(a.garipov): Add tests.
//
// TODO(a.garipov): Make other middlewares more compact as well.  See AGDNS-328.
type initMw struct {
	// messages is used to build the responses specific for the request's
	// context.
	messages *dnsmsg.Constructor

	// fltGrp is the filtering group to which srv belongs.
	fltGrp *agd.FilteringGroup

	// srvGrp is the server group to which srv belongs.
	srvGrp *agd.ServerGroup

	// srv is the current server which serves the request.
	srv *agd.Server

	// db is the storage of user profiles.
	db agd.ProfileDB

	// geoIP detects the location of the request source.
	geoIP geoip.Interface

	// errColl collects and reports the errors considered non-critical.
	errColl agd.ErrorCollector
}

// type check
var _ dnsserver.Middleware = (*initMw)(nil)

// Wrap implements the dnsserver.Middleware interface for *initMw.
func (mw *initMw) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
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
		fqdn := strings.ToLower(q.Name)
		qt := q.Qtype
		cl := q.Qclass

		if specHdlr, name := mw.noReqInfoSpecialHandler(fqdn, qt, cl); specHdlr != nil {
			optlog.Debug1("init mw: got no-req-info special handler %s", name)

			// Don't wrap the error, because it's informative enough as is, and
			// because if handled is true, the main flow terminates here.
			return specHdlr(ctx, rw, req)
		}

		// Get the request's information, such as GeoIP data and user profiles.
		ri, err := mw.newRequestInfo(ctx, req, rw.RemoteAddr(), fqdn, qt)
		if err != nil {
			var ecsErr dnsmsg.BadECSError
			if errors.As(err, &ecsErr) {
				// We've got a bad ECS option.  Log and respond with a FORMERR
				// immediately.
				optlog.Debug1("init mw: %s", err)

				err = rw.WriteMsg(ctx, req, mw.messages.NewMsgFORMERR(req))
				err = errors.Annotate(err, "writing formerr resp: %w")
			}

			// Don't wrap the error, because this is the main flow, and there is
			// already errors.Annotate here.
			return err
		}

		if specHdlr, name := mw.reqInfoSpecialHandler(ri, cl); specHdlr != nil {
			optlog.Debug1("init mw: got req-info special handler %s", name)

			// Don't wrap the error, because it's informative enough as is, and
			// because if handled is true, the main flow terminates here.
			return specHdlr(ctx, rw, req, ri)
		}

		ctx = agd.ContextWithRequestInfo(ctx, ri)

		// Record the response, restore the AD bit value in both the request and
		// the response, and write the response.
		nwrw := makeNonWriter(rw)
		err = h.ServeDNS(ctx, nwrw, req)
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
func (mw *initMw) newRequestInfo(
	ctx context.Context,
	req *dns.Msg,
	raddr net.Addr,
	fqdn string,
	qt dnsmsg.RRType,
) (ri *agd.RequestInfo, err error) {
	// Put the host, server, and client IP data into the request information
	// immediately.
	ri = &agd.RequestInfo{
		FilteringGroup: mw.fltGrp,
		Messages:       mw.messages,
		ServerGroup:    mw.srvGrp.Name,
		Server:         mw.srv.Name,
		Host:           strings.TrimSuffix(fqdn, "."),
		QType:          qt,
	}

	ri.RemoteIP = netutil.NetAddrToAddrPort(raddr).Addr()

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
	err = mw.addProfile(ctx, ri, req)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return ri, nil
}

// addLocation adds GeoIP location information about the client's remote address
// as well as the EDNS Client Subnet information, if there is one, to ri.  err
// is not nil only if req contains a malformed EDNS Client Subnet option.
func (mw *initMw) addLocation(ctx context.Context, ri *agd.RequestInfo, req *dns.Msg) (err error) {
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
func (mw *initMw) locationData(ctx context.Context, ip netip.Addr, typ string) (l *agd.Location) {
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

// addProfile adds profile and device information, if any, to the request
// information.
func (mw *initMw) addProfile(ctx context.Context, ri *agd.RequestInfo, req *dns.Msg) (err error) {
	defer func() { err = errors.Annotate(err, "getting profile from req: %w") }()

	var id agd.DeviceID
	if p := mw.srv.Protocol; p.IsStdEncrypted() {
		// Assume that mw.srvGrp.TLS is non-nil if p.IsStdEncrypted() is true.
		wildcards := mw.srvGrp.TLS.DeviceIDWildcards
		id, err = deviceIDFromContext(ctx, mw.srv.Protocol, wildcards)
	} else if p == agd.ProtoDNS {
		id, err = deviceIDFromEDNS(req)
	} else {
		// No DeviceID for DNSCrypt yet.
		return nil
	}

	if err != nil {
		return err
	}

	optlog.Debug2("init mw: got device id %q and ip %s", id, ri.RemoteIP)

	prof, dev, byWhat, err := mw.profile(ctx, ri.RemoteIP, id, mw.srv.Protocol)
	if err != nil {
		// Use two errors.Is calls to prevent unnecessary allocations.
		if !errors.Is(err, agd.DeviceNotFoundError{}) &&
			!errors.Is(err, agd.ProfileNotFoundError{}) {
			// Very unlikely, since those two error types are the only ones
			// currently returned from the profile DB.
			return err
		}

		optlog.Debug1("init mw: profile or device not found: %s", err)
	} else if prof.Deleted {
		optlog.Debug1("init mw: profile %s is deleted", prof.ID)
	} else {
		optlog.Debug3("init mw: found profile %s and device %s by %s", prof.ID, dev.ID, byWhat)

		ri.Device, ri.Profile = dev, prof
		ri.Messages = &dnsmsg.Constructor{
			FilteredResponseTTL: prof.FilteredResponseTTL,
		}
	}

	return nil
}

// profile finds the profile by the client data.
func (mw *initMw) profile(
	ctx context.Context,
	ip netip.Addr,
	id agd.DeviceID,
	p agd.Protocol,
) (prof *agd.Profile, dev *agd.Device, byWhat string, err error) {
	if id != "" {
		prof, dev, err = mw.db.ProfileByDeviceID(ctx, id)

		return prof, dev, "device id", err
	}

	if !mw.srv.LinkedIPEnabled {
		optlog.Debug1("init mw: not matching by ip for server %s", mw.srv.Name)

		return nil, nil, "", agd.ProfileNotFoundError{}
	} else if p != agd.ProtoDNS {
		optlog.Debug1("init mw: not matching by ip for proto %v", p)

		return nil, nil, "", agd.ProfileNotFoundError{}
	}

	prof, dev, err = mw.db.ProfileByIP(ctx, ip)

	return prof, dev, "linked ip", err
}
