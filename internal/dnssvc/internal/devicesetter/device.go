package devicesetter

import (
	"context"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
)

// findDevice returns a valid, non-deleted profile and device or nils.  err is
// only not nil when it's not [profiledb.ErrDeviceNotFound].
func (ds *Default) findDevice(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
	id agd.DeviceID,
) (prof *agd.Profile, dev *agd.Device, err error) {
	// TODO(a.garipov): Add package optslog for optimized slog logging?
	optlog.Debug3("devicesetter: got dev id %q, raddr %s, and laddr %s", id, remoteIP, laddr)

	prof, dev, byWhat, err := ds.deviceFromDB(ctx, laddr, remoteIP, id)
	if err != nil {
		if !errors.Is(err, profiledb.ErrDeviceNotFound) {
			// Don't wrap the error, because it's likely [errUnknownDedicated].
			return nil, nil, err
		}

		optlog.Debug1("devicesetter: profile or device not found: %s", err)

		return nil, nil, nil
	}

	if prof.Deleted {
		optlog.Debug1("devicesetter: profile %s is deleted", prof.ID)

		return nil, nil, nil
	}

	optlog.Debug3("devicesetter: found profile %s and device %s by %s", prof.ID, dev.ID, byWhat)

	return prof, dev, nil
}

// Constants for the parameter by which a device has been found.
const (
	byDeviceID    = "device id"
	byDedicatedIP = "dedicated ip"
	byLinkedIP    = "linked ip"
)

// deviceFromDB queries the profile DB for the profile and device by the client
// data.  It also returns the description of how it has found them.
func (ds *Default) deviceFromDB(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
	id agd.DeviceID,
) (prof *agd.Profile, dev *agd.Device, byWhat string, err error) {
	if id != "" {
		prof, dev, err = ds.db.ProfileByDeviceID(ctx, id)
		if err != nil {
			return nil, nil, "", err
		}

		return prof, dev, byDeviceID, nil
	}

	if ds.srv.Protocol == agd.ProtoDNS {
		return ds.deviceByAddrs(ctx, laddr, remoteIP)
	}

	return nil, nil, "", profiledb.ErrDeviceNotFound
}

// deviceByAddrs finds the profile and the device by the remote and local
// addresses depending on the data and the server settings.
func (ds *Default) deviceByAddrs(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
) (prof *agd.Profile, dev *agd.Device, byWhat string, err error) {
	if ds.srv.BindsToInterfaces() && !ds.srv.HasAddr(laddr) {
		prof, dev, err = ds.deviceByLocalAddr(ctx, laddr.Addr())
		if err != nil {
			return nil, nil, "", err
		}

		return prof, dev, byDedicatedIP, nil
	}

	if !ds.srv.LinkedIPEnabled {
		return nil, nil, "", profiledb.ErrDeviceNotFound
	}

	prof, dev, err = ds.db.ProfileByLinkedIP(ctx, remoteIP)
	if err != nil {
		return nil, nil, "", err
	}

	return prof, dev, byLinkedIP, nil
}

// deviceByLocalAddr finds the profile and the device by the local address.
func (ds *Default) deviceByLocalAddr(
	ctx context.Context,
	localIP netip.Addr,
) (prof *agd.Profile, dev *agd.Device, err error) {
	prof, dev, err = ds.db.ProfileByDedicatedIP(ctx, localIP)
	if err != nil {
		if errors.Is(err, profiledb.ErrDeviceNotFound) {
			optlog.Debug1("devicesetter: unknown dedicated ip for server %s; dropping", ds.srv.Name)

			err = ErrUnknownDedicated
		}

		return nil, nil, err
	}

	return prof, dev, nil
}

// setDevice authenticates the device, if necessary, and sets profile and
// device data in ri using the information from the arguments.  It also logs its
// decisions.  All arguments must not be nil.
func (ds *Default) setDevice(
	ctx context.Context,
	ri *agd.RequestInfo,
	srvReqInfo *dnsserver.RequestInfo,
	prof *agd.Profile,
	dev *agd.Device,
) {
	if !ds.authDevice(ctx, srvReqInfo, dev) {
		metrics.DNSSvcDoHAuthFailsTotal.Inc()

		optlog.Debug1("devicesetter: device %s: authentication failed", dev.ID)

		return
	}

	ri.Profile = prof
	ri.Device = dev

	// TODO(a.garipov): Consider using the global cloner here once it is tested
	// and optimized.
	ri.Messages = dnsmsg.NewConstructor(nil, prof.BlockingMode, prof.FilteredResponseTTL)
}

// authDevice returns true if ctx passes device authentication configuration.
// all arguments must not be nil.
func (ds *Default) authDevice(
	ctx context.Context,
	srvReqInfo *dnsserver.RequestInfo,
	dev *agd.Device,
) (ok bool) {
	conf := dev.Auth
	if !conf.Enabled {
		return true
	}

	if ds.srv.Protocol != agd.ProtoDoH {
		// Pass non-DoH-only devices regardless of the userinfo and block
		// DoH-only devices in case of non-DoH protocol.
		return !conf.DoHAuthOnly
	}

	userinfo := srvReqInfo.Userinfo
	if userinfo == nil {
		// Require presence of userinfo if DoHAuthOnly is enabled.  Otherwise,
		// pass.
		return !conf.DoHAuthOnly
	}

	// NOTE: It is currently assumed that if the execution got here, the device
	// ID and thus the device were found using the userinfo.
	password, set := userinfo.Password()
	if !set {
		return false
	}

	return conf.PasswordHash.Authenticate(ctx, []byte(password))
}
