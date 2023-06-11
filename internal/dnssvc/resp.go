package dnssvc

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/miekg/dns"
)

// Response Handling

// writeFilteredResp writes the response to rw if reqRes and respRes require
// that.  written is the DNS message that was actually sent to the client.
func writeFilteredResp(
	ctx context.Context,
	ri *agd.RequestInfo,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	resp *dns.Msg,
	reqRes filter.Result,
	respRes filter.Result,
) (written *dns.Msg, err error) {
	switch reqRes := reqRes.(type) {
	case nil:
		return writeFilteredRespNoReq(ctx, ri, rw, req, resp, respRes)
	case *filter.ResultBlocked:
		written, err = writeBlockedResp(ctx, ri, rw, req)
	case *filter.ResultAllowed:
		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			err = fmt.Errorf("writing response to allowed request: %w", err)
		} else {
			written = resp
		}
	case *filter.ResultModified:
		if reqRes.Msg.Response {
			// Only use the request filtering result in case it's already a
			// response.  Otherwise, it's a CNAME rewrite result, which isn't
			// filtered after resolving.
			resp = reqRes.Msg
		}

		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			err = fmt.Errorf("writing response to modified request: %w", err)
		} else {
			written = resp
		}
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(&agd.ArgumentError{
			Name:    "reqRes",
			Message: fmt.Sprintf("unexpected type %T", reqRes),
		})
	}

	return written, err
}

// writeFilteredRespNoReq writes the response to rw if respRes requires that.
// written is the DNS message that was actually sent to the client.
func writeFilteredRespNoReq(
	ctx context.Context,
	ri *agd.RequestInfo,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	resp *dns.Msg,
	respRes filter.Result,
) (written *dns.Msg, err error) {
	switch respRes := respRes.(type) {
	case nil, *filter.ResultAllowed:
		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			err = fmt.Errorf("writing allowed or not filtered response: %w", err)
		} else {
			written = resp
		}
	case *filter.ResultBlocked:
		written, err = writeBlockedResp(ctx, ri, rw, req)
	case *filter.ResultModified:
		err = rw.WriteMsg(ctx, req, respRes.Msg)
		if err != nil {
			err = fmt.Errorf("writing modified response: %w", err)
		} else {
			written = respRes.Msg
		}
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(&agd.ArgumentError{
			Name:    "respRes",
			Message: fmt.Sprintf("unexpected type %T", respRes),
		})
	}

	return written, err
}

// writeBlockedResp writes the appropriate blocked response to the response
// writer and returns it.
func writeBlockedResp(
	ctx context.Context,
	ri *agd.RequestInfo,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	resp, err = ri.Messages.NewBlockedRespMsg(req)
	if err != nil {
		return nil, fmt.Errorf("creating blocked response: %w", err)
	}

	err = rw.WriteMsg(ctx, req, resp)
	if err != nil {
		return nil, fmt.Errorf("writing blocked response: %w", err)
	}

	return resp, nil
}
