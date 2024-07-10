package devicesetter

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// findDevice returns a valid, non-deleted profile and device or nils.  err is
// only not nil when it's not a not-found error from the profile database.
func (ds *Default) findDevice(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
	id agd.DeviceID,
	extID *extHumanID,
) (prof *agd.Profile, dev *agd.Device, err error) {
	// TODO(a.garipov): Add package optslog for optimized slog logging?
	optlog.Debug4(
		"devicesetter: got dev id %q, ext id present %t, raddr %s, and laddr %s",
		id,
		extID != nil,
		remoteIP,
		laddr,
	)

	prof, dev, byWhat, err := ds.deviceFromDB(ctx, laddr, remoteIP, id, extID)
	if err != nil {
		// Don't wrap the error, because it's likely [ErrUnknownDedicated].
		return nil, nil, err
	}

	if prof == nil || dev == nil {
		log.Debug("devicesetter: profile or device not found")

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
	byDedicatedIP = "dedicated ip"
	byDeviceID    = "device id"
	byHumanID     = "human id"
	byLinkedIP    = "linked ip"
)

// deviceFromDB queries the profile DB for the profile and device by the client
// data.  It also returns the description of how it has found them.  err is only
// not nil when it's not a not-found error from the profile database.
func (ds *Default) deviceFromDB(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
	id agd.DeviceID,
	extID *extHumanID,
) (prof *agd.Profile, dev *agd.Device, byWhat string, err error) {
	if id != "" {
		prof, dev, err = ds.db.ProfileByDeviceID(ctx, id)
		if err != nil {
			// Don't wrap the error, as this is a hot path, and an error other
			// than a not-found one is unlikely.
			return nil, nil, "", removeNotFound(err)
		}

		return prof, dev, byDeviceID, nil
	}

	if extID != nil {
		prof, dev, err = ds.deviceByExtID(ctx, extID)
		if err == nil {
			return prof, dev, byHumanID, nil
		}

		// Don't wrap the error, because it's informative enough as is.
		return nil, nil, "", err
	}

	if ds.srv.Protocol == agd.ProtoDNS {
		return ds.deviceByAddrs(ctx, laddr, remoteIP)
	}

	return nil, nil, "", nil
}

// removeNotFound returns nil if err is one of the not-found errors from the
// profile database.
func removeNotFound(err error) (res error) {
	if isProfileDBNotFound(err) {
		return nil
	}

	return err
}

// deviceByExtID queries the profile DB for the profile and device by the
// extended human-readable device identifier.  extID must not be nil.  err is
// only not nil when it's not a not-found error from the profile database.
func (ds *Default) deviceByExtID(
	ctx context.Context,
	extID *extHumanID,
) (prof *agd.Profile, dev *agd.Device, err error) {
	profID, humanID := extID.ProfileID, extID.HumanID
	prof, dev, err = ds.db.ProfileByHumanID(ctx, profID, agd.HumanIDToLower(humanID))
	switch {
	case err == nil:
		return prof, dev, nil
	case errorIsOpt(err, profiledb.ErrProfileNotFound):
		// No such profile, return immediately.
		return nil, nil, nil
	case errorIsOpt(err, profiledb.ErrDeviceNotFound):
		// Go on and try to create.
	default:
		// Unlikely, so wrap.
		return nil, nil, fmt.Errorf("querying profile db by human id: %w", err)
	}

	prof, dev, err = ds.db.CreateAutoDevice(ctx, profID, humanID, extID.DeviceType)
	switch {
	case err == nil:
		return prof, dev, nil
	case errorIsOpt(err, profiledb.ErrProfileNotFound):
		// A rare case where a profile has been deleted between the check and
		// the creation.
		return nil, nil, nil
	default:
		return nil, nil, fmt.Errorf("creating autodevice: %w", err)
	}
}

// isProfileDBNotFound returns true if err is one of the not-found errors from
// the profile database.
func isProfileDBNotFound(err error) (ok bool) {
	return errorIsOpt(err, profiledb.ErrDeviceNotFound) ||
		errorIsOpt(err, profiledb.ErrProfileNotFound)
}

// errorIsOpt is an optimized version of [errors.Is] that is faster in cases
// where the error is returned directly or with one level of [fmt.Errorf].
// target must be comparable.
func errorIsOpt(err, target error) (ok bool) {
	if err == target {
		return true
	}

	unwrapped := errors.Unwrap(err)
	if unwrapped == target {
		return true
	}

	return unwrapped != nil && errors.Is(unwrapped, target)
}

// deviceByAddrs finds the profile and the device by the remote and local
// addresses depending on the data and the server settings.  err is only not nil
// when it's not a not-found error from the profile database.
func (ds *Default) deviceByAddrs(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
) (prof *agd.Profile, dev *agd.Device, byWhat string, err error) {
	if ds.srv.BindsToInterfaces() && !ds.srv.HasAddr(laddr) {
		prof, dev, err = ds.deviceByLocalAddr(ctx, laddr.Addr())
		if err != nil {
			// Don't wrap the error, as this is a hot path, and an error about
			// an unknown dedicated address might be common here.
			return nil, nil, "", err
		}

		return prof, dev, byDedicatedIP, nil
	}

	if !ds.srv.LinkedIPEnabled {
		return nil, nil, "", nil
	}

	prof, dev, err = ds.db.ProfileByLinkedIP(ctx, remoteIP)
	if err != nil {
		// Don't wrap the error, as this is a hot path, and an error other than
		// a not-found one is unlikely.
		return nil, nil, "", removeNotFound(err)
	}

	return prof, dev, byLinkedIP, nil
}

// deviceByLocalAddr finds the profile and the device by the local address.
// deviceByLocalAddr replaces profiledb's not-found errors with
// [ErrUnknownDedicated].
func (ds *Default) deviceByLocalAddr(
	ctx context.Context,
	localIP netip.Addr,
) (prof *agd.Profile, dev *agd.Device, err error) {
	prof, dev, err = ds.db.ProfileByDedicatedIP(ctx, localIP)
	if err != nil {
		if isProfileDBNotFound(err) {
			optlog.Debug1("devicesetter: unknown dedicated ip for server %s; dropping", ds.srv.Name)

			err = ErrUnknownDedicated
		}

		// Don't wrap the error, as this is a hot path, and a not-found error is
		// common here.
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
