package devicefinder

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// findDevice looks up the device and profile data in the profile database and
// returns a valid device result.
func (f *Default) findDevice(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
	id agd.DeviceID,
	extID *extHumanID,
) (r agd.DeviceResult) {
	optslog.Debug4(
		ctx,
		f.logger,
		"finding device",
		"dev_id", id,
		"ext_id_present", extID != nil,
		"remote_ip", remoteIP,
		"laddr", laddr,
	)

	r = f.deviceFromDB(ctx, laddr, remoteIP, id, extID)
	switch r := r.(type) {
	case nil:
		f.logger.DebugContext(ctx, "profile or device not found")

		return nil
	case *agd.DeviceResultOK:
		if p := r.Profile; p.Deleted {
			optslog.Debug1(ctx, f.logger, "profile is deleted", "prof_id", p.ID)

			return nil
		}
	}

	return r
}

// deviceFromDB queries the profile DB for the profile and device by the client
// data.
func (f *Default) deviceFromDB(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
	id agd.DeviceID,
	extID *extHumanID,
) (r agd.DeviceResult) {
	if id != "" {
		prof, dev, err := f.db.ProfileByDeviceID(ctx, id)

		return f.newDeviceResult(ctx, prof, dev, "device id", err)
	}

	if extID != nil {
		prof, dev, err := f.deviceByExtID(ctx, extID)

		return f.newDeviceResult(ctx, prof, dev, "human id", err)
	}

	if f.srv.Protocol == agd.ProtoDNS {
		return f.deviceByAddrs(ctx, laddr, remoteIP)
	}

	return nil
}

// newDeviceResult is a helper that returns a result based on the error and the
// device data.  It also logs the way in which the device has been found.
func (f *Default) newDeviceResult(
	ctx context.Context,
	p *agd.Profile,
	d *agd.Device,
	byWhat string,
	err error,
) (r agd.DeviceResult) {
	if err == nil {
		if p == nil {
			return nil
		}

		optslog.Debug3(ctx, f.logger, "found", "prof_id", p.ID, "dev_id", d.ID, "by", byWhat)

		return &agd.DeviceResultOK{
			Device:  d,
			Profile: p,
		}
	}

	if isProfileDBNotFound(err) {
		return nil
	}

	return &agd.DeviceResultError{
		Err: err,
	}
}

// deviceByExtID queries the profile DB for the profile and device by the
// extended human-readable device identifier.  extID must not be nil.  err is
// only not nil when it's not a not-found error from the profile database.
func (f *Default) deviceByExtID(
	ctx context.Context,
	extID *extHumanID,
) (prof *agd.Profile, dev *agd.Device, err error) {
	profID, humanID := extID.ProfileID, extID.HumanID
	prof, dev, err = f.db.ProfileByHumanID(ctx, profID, agd.HumanIDToLower(humanID))
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

	prof, dev, err = f.db.CreateAutoDevice(ctx, profID, humanID, extID.DeviceType)
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
// addresses depending on the data and the server settings.
func (f *Default) deviceByAddrs(
	ctx context.Context,
	laddr netip.AddrPort,
	remoteIP netip.Addr,
) (r agd.DeviceResult) {
	if f.srv.BindsToInterfaces() && !f.srv.HasAddr(laddr) {
		return f.deviceByLocalAddr(ctx, laddr.Addr())
	}

	if !f.srv.LinkedIPEnabled {
		return nil
	}

	prof, dev, err := f.db.ProfileByLinkedIP(ctx, remoteIP)

	return f.newDeviceResult(ctx, prof, dev, "linked ip", err)
}

// deviceByLocalAddr finds the profile and the device by the local address.
func (f *Default) deviceByLocalAddr(
	ctx context.Context,
	localIP netip.Addr,
) (r agd.DeviceResult) {
	p, d, err := f.db.ProfileByDedicatedIP(ctx, localIP)
	if err == nil {
		optslog.Debug3(
			ctx,
			f.logger,
			"found",
			"prof_id", p.ID,
			"dev_id", d.ID,
			"by", "dedicated ip",
		)

		return &agd.DeviceResultOK{
			Device:  d,
			Profile: p,
		}
	}

	if !isProfileDBNotFound(err) {
		// Unlikely, so wrap.
		return &agd.DeviceResultError{
			Err: fmt.Errorf("looking up by dedicated ip: %w", err),
		}
	}

	optslog.Debug2(
		ctx,
		f.logger,
		"unknown dedicated ip; dropping",
		"local_ip", localIP,
		"server", f.srv.Name,
	)

	return &agd.DeviceResultUnknownDedicated{
		Err: err,
	}
}

// authenticatedResult authenticates the device, if necessary, and returns the
// corresponding result.  It also logs its decisions.  All arguments must not be
// nil.
func (f *Default) authenticatedResult(
	ctx context.Context,
	srvReqInfo *dnsserver.RequestInfo,
	res *agd.DeviceResultOK,
) (r agd.DeviceResult) {
	dev := res.Device
	err := f.authenticate(ctx, srvReqInfo, dev)
	if err != nil {
		metrics.DNSSvcDoHAuthFailsTotal.Inc()

		optslog.Debug2(
			ctx,
			f.logger,
			"authentication failed",
			"dev_id", dev.ID,
			slogutil.KeyError, err,
		)

		return &agd.DeviceResultAuthenticationFailure{
			Err: err,
		}
	}

	return res
}

// authenticate returns an error if the device passes authentication.  all
// arguments must not be nil.
func (f *Default) authenticate(
	ctx context.Context,
	srvReqInfo *dnsserver.RequestInfo,
	dev *agd.Device,
) (err error) {
	conf := dev.Auth
	if !conf.Enabled {
		return nil
	}

	if f.srv.Protocol != agd.ProtoDoH {
		if conf.DoHAuthOnly {
			return ErrNotDoH
		}

		return nil
	}

	userinfo := srvReqInfo.Userinfo
	if userinfo == nil {
		if conf.DoHAuthOnly {
			return ErrNoUserInfo
		}

		return nil
	}

	// NOTE: It is currently assumed that if the execution got here, the device
	// ID and thus the device were found using the userinfo.
	password, set := userinfo.Password()
	if !set {
		return ErrNoPassword
	}

	if !conf.PasswordHash.Authenticate(ctx, []byte(password)) {
		return ErrAuthenticationFailed
	}

	return nil
}
