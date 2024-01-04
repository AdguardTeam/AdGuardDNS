package initial

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// addProfile adds profile and device information, if any, to the request
// information.
func (mw *Middleware) addProfile(
	ctx context.Context,
	ri *agd.RequestInfo,
	req *dns.Msg,
	localAddr netip.AddrPort,
) (err error) {
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

	optlog.Debug3("init mw: got device id %q, raddr %s, and laddr %s", id, ri.RemoteIP, localAddr)

	prof, dev, byWhat, err := mw.profile(ctx, localAddr, ri.RemoteIP, id)
	if err != nil {
		if !errors.Is(err, profiledb.ErrDeviceNotFound) {
			// Very unlikely, since there is only one error type currently
			// returned from the default profile DB.
			return fmt.Errorf("unexpected profiledb error: %w", err)
		}

		optlog.Debug1("init mw: profile or device not found: %s", err)
	} else if prof.Deleted {
		optlog.Debug1("init mw: profile %s is deleted", prof.ID)
	} else {
		optlog.Debug3("init mw: found profile %s and device %s by %s", prof.ID, dev.ID, byWhat)

		ri.Device, ri.Profile = dev, prof

		// TODO(a.garipov): Consider using the global cloner here once it is
		// tested and optimized.
		ri.Messages = dnsmsg.NewConstructor(nil, prof.BlockingMode, prof.FilteredResponseTTL)
	}

	return nil
}

// Constants for the parameter by which a device has been found.
const (
	byDeviceID    = "device id"
	byDedicatedIP = "dedicated ip"
	byLinkedIP    = "linked ip"
)

// errUnknownDedicated is returned by [Middleware.profile] if the request should
// be dropped, because it's a request for an unknown dedicated IP address.
const errUnknownDedicated errors.Error = "drop"

// profile finds the profile by the client data.
func (mw *Middleware) profile(
	ctx context.Context,
	localAddr netip.AddrPort,
	remoteIP netip.Addr,
	id agd.DeviceID,
) (prof *agd.Profile, dev *agd.Device, byWhat string, err error) {
	if id != "" {
		prof, dev, err = mw.db.ProfileByDeviceID(ctx, id)
		if err != nil {
			return nil, nil, "", err
		}

		return prof, dev, byDeviceID, nil
	}

	if mw.srv.Protocol == agd.ProtoDNS {
		return mw.profileByAddrs(ctx, localAddr, remoteIP)
	}

	return nil, nil, "", profiledb.ErrDeviceNotFound
}

// profileByAddrs finds the profile by the remote and local addresses.
func (mw *Middleware) profileByAddrs(
	ctx context.Context,
	localAddr netip.AddrPort,
	remoteIP netip.Addr,
) (prof *agd.Profile, dev *agd.Device, byWhat string, err error) {
	if mw.srv.BindsToInterfaces() && !mw.srv.HasAddr(localAddr) {
		prof, dev, err = mw.db.ProfileByDedicatedIP(ctx, localAddr.Addr())
		if err == nil {
			return prof, dev, byDedicatedIP, nil
		} else if errors.Is(err, profiledb.ErrDeviceNotFound) {
			optlog.Debug1("init mw: unknown dedicated ip for server %s; dropping", mw.srv.Name)

			err = errUnknownDedicated
		}

		return nil, nil, "", err
	}

	if !mw.srv.LinkedIPEnabled {
		return nil, nil, "", profiledb.ErrDeviceNotFound
	}

	prof, dev, err = mw.db.ProfileByLinkedIP(ctx, remoteIP)
	if err != nil {
		return nil, nil, "", err
	}

	return prof, dev, byLinkedIP, nil
}
