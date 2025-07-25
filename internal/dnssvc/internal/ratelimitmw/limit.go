package ratelimitmw

import (
	"context"
	"fmt"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/miekg/dns"
)

// serveWithRatelimiting applies global and profile ratelimiting logic and calls
// next if necessary.
func (mw *Middleware) serveWithRatelimiting(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
	next dnsserver.Handler,
) (err error) {
	if !slices.Contains(mw.protos, ri.ServerInfo.Protocol) {
		return next.ServeDNS(ctx, rw, req)
	}

	shouldReturn, err := mw.serveWithProfileRatelimiting(ctx, rw, req, ri, next)
	if err != nil {
		return fmt.Errorf("profile ratelimit: %w", err)
	} else if shouldReturn {
		return nil
	}

	return mw.serveWithGlobalRatelimiting(ctx, rw, req, ri, next)
}

// serveWithRatelimiting applies global ratelimiting logic and calls next if
// necessary.
func (mw *Middleware) serveWithGlobalRatelimiting(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
	next dnsserver.Handler,
) (err error) {
	shouldDrop, isAllowlisted, err := mw.limiter.IsRateLimited(ctx, req, ri.RemoteIP)
	if err != nil {
		return fmt.Errorf("checking global ratelimit: %w", err)
	} else if shouldDrop {
		mw.metrics.OnRateLimited(ctx, req, rw)
		optslog.Debug1(ctx, mw.logger, "ratelimited globally", "remote_ip", ri.RemoteIP)

		return nil
	} else if isAllowlisted {
		// If the request is allowlisted, we can pass it through to the next
		// handler immediately.
		mw.metrics.OnAllowlisted(ctx, req, rw)

		return next.ServeDNS(ctx, rw, req)
	}

	nwrw := dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
	err = next.ServeDNS(ctx, nwrw, req)
	if err != nil {
		// Don't wrap the error, because this is the main flow, and there is
		// [errors.Annotate].
		return err
	}

	resp := nwrw.Msg()
	if resp == nil {
		return nil
	}

	mw.limiter.CountResponses(ctx, resp, ri.RemoteIP)

	return rw.WriteMsg(ctx, req, resp)
}

// serveWithProfileRatelimiting applies the custom ratelimiting logic of the
// profile if there is one and calls next if necessary.  shouldReturn is true if
// the processing of the query should be stopped.
func (mw *Middleware) serveWithProfileRatelimiting(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
	next dnsserver.Handler,
) (shouldReturn bool, err error) {
	prof, _ := ri.DeviceData()
	if prof == nil {
		return false, nil
	}

	res := prof.Ratelimiter.Check(ctx, req, ri.RemoteIP)
	switch res {
	case agd.RatelimitResultDrop:
		mw.metrics.IncrementRatelimitedByProfile(ctx)
		optslog.Debug2(
			ctx,
			mw.logger,
			"ratelimited by profile",
			"remote_ip", ri.RemoteIP,
			"profile_id", prof.ID,
		)

		return true, nil
	case agd.RatelimitResultUseGlobal:
		return false, nil
	case agd.RatelimitResultPass:
		// Go on.
	default:
		panic(fmt.Errorf(
			"ratelimitmw: ratelimit result: %w: got %T(%[2]v)",
			errors.ErrBadEnumValue,
			res,
		))
	}

	nwrw := dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
	err = next.ServeDNS(ctx, nwrw, req)
	if err != nil {
		return true, fmt.Errorf("serving: %w", err)
	}

	resp := nwrw.Msg()
	if resp == nil {
		return true, nil
	}

	prof.Ratelimiter.CountResponses(ctx, resp, ri.RemoteIP)

	err = rw.WriteMsg(ctx, req, resp)
	if err != nil {
		return true, fmt.Errorf("writing resp: %w", err)
	}

	return true, nil
}
