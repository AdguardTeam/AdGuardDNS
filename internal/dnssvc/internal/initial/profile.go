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
	localIP netip.Addr,
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

	optlog.Debug3("init mw: got device id %q, raddr %s, and laddr %s", id, ri.RemoteIP, localIP)

	prof, dev, byWhat, err := mw.profile(ctx, localIP, ri.RemoteIP, id)
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
		ri.Messages = dnsmsg.NewConstructor(prof.BlockingMode.Mode, prof.FilteredResponseTTL)
	}

	return nil
}

// Constants for the parameter by which a device has been found.
const (
	byDeviceID    = "device id"
	byDedicatedIP = "dedicated ip"
	byLinkedIP    = "linked ip"
)

// profile finds the profile by the client data.
func (mw *Middleware) profile(
	ctx context.Context,
	localIP netip.Addr,
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

	if !mw.srv.LinkedIPEnabled {
		optlog.Debug1("init mw: not matching by linked or dedicated ip for server %s", mw.srv.Name)

		return nil, nil, "", profiledb.ErrDeviceNotFound
	} else if p := mw.srv.Protocol; p != agd.ProtoDNS {
		optlog.Debug1("init mw: not matching by linked or dedicated ip for proto %v", p)

		return nil, nil, "", profiledb.ErrDeviceNotFound
	}

	byWhat = byDedicatedIP
	prof, dev, err = mw.db.ProfileByDedicatedIP(ctx, localIP)
	if errors.Is(err, profiledb.ErrDeviceNotFound) {
		byWhat = byLinkedIP
		prof, dev, err = mw.db.ProfileByLinkedIP(ctx, remoteIP)
	}

	if err != nil {
		return nil, nil, "", err
	}

	return prof, dev, byWhat, nil
}
