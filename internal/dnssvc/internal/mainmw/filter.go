package mainmw

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/miekg/dns"
)

// filteringContext contains information regarding request and response
// filtering.
type filteringContext struct {
	originalRequest *dns.Msg
	modifiedRequest *dns.Msg

	originalResponse *dns.Msg
	filteredResponse *dns.Msg

	requestResult  filter.Result
	responseResult filter.Result

	elapsed time.Duration

	isDebug bool
}

// newFilteringContext returns a new filtering context initialized with the data
// from req.
func (mw *Middleware) newFilteringContext(req *dns.Msg) (fctx *filteringContext) {
	fctx = mw.fltCtxPool.Get()
	*fctx = filteringContext{}

	isDebug := req.Question[0].Qclass == dns.ClassCHAOS
	if isDebug {
		req.Question[0].Qclass = dns.ClassINET
	}

	fctx.originalRequest = req
	fctx.isDebug = isDebug

	return fctx
}

// filterRequest applies f to req and sets the result of filtering in fctx.  If
// the result is the CNAME rewrite, it also sets the modified request to
// resolve.  It also adds the time elapsed on filtering.  All errors are
// reported using [Middleware.reportf].
func (mw *Middleware) filterRequest(
	ctx context.Context,
	fctx *filteringContext,
	f filter.Interface,
	ri *agd.RequestInfo,
) {
	start := time.Now()

	fltReq := mw.reqInfoToFltReq(fctx.originalRequest, ri)
	defer mw.putFltReq(fltReq)

	reqRes, err := f.FilterRequest(ctx, fltReq)
	if err != nil {
		errcoll.Collect(ctx, mw.errColl, mw.logger, "filtering request", err)
	}

	if mod, ok := reqRes.(*filter.ResultModifiedRequest); ok {
		fctx.modifiedRequest = mod.Msg
	}

	fctx.requestResult = reqRes
	fctx.elapsed += time.Since(start)
}

// reqInfoToFltReq converts data from a DNS request and request info into a
// *filter.Request.  The returned request data should be put back into the pool
// by using [Middleware.putFltReq].
func (mw *Middleware) reqInfoToFltReq(req *dns.Msg, ri *agd.RequestInfo) (fltReq *filter.Request) {
	fltReq = mw.fltReqPool.Get()

	// NOTE:  Fill all fields of fltReq since it is reused from the pool.
	fltReq.DNS = req
	fltReq.Messages = ri.Messages
	fltReq.RemoteIP = ri.RemoteIP

	if _, d := ri.DeviceData(); d != nil {
		fltReq.ClientName = string(d.Name)
	} else {
		fltReq.ClientName = ""
	}

	fltReq.Host = ri.Host
	fltReq.QType = ri.QType
	fltReq.QClass = ri.QClass

	return fltReq
}

// putFltReq sets req.DNS to nil, to prevent the message being contained in the
// pool, which can lead to conflicts with the cloner of the middleware, and puts
// req back into the pool.
func (mw *Middleware) putFltReq(req *filter.Request) {
	req.DNS = nil
	mw.fltReqPool.Put(req)
}

// filterResponse applies f to resp and sets the result of filtering in fctx.
// If origReq has a different question name than resp, the request assumed being
// CNAME-rewritten and no filtering performed on resp, the CNAME is prepended to
// resp answer section instead.  It also sets the time elapsed on filtering.
// All errors are reported using [Middleware.reportf].
func (mw *Middleware) filterResponse(
	ctx context.Context,
	fctx *filteringContext,
	f filter.Interface,
	ri *agd.RequestInfo,
) {
	start := time.Now()

	if modReq := fctx.modifiedRequest; modReq != nil {
		// Return the request ID and target name to their original values, since
		// the request has previously been rewritten by a CNAME rewrite rule.
		origReq := fctx.originalRequest
		origResp := fctx.originalResponse
		origResp.Id = origReq.Id
		origResp.Question[0] = origReq.Question[0]

		// Prepend the CNAME answer to the response and don't filter it.
		var rr dns.RR = ri.Messages.NewAnswerCNAME(origReq, modReq.Question[0].Name)
		origResp.Answer = slices.Insert(origResp.Answer, 0, rr)
	} else {
		fltResp := mw.reqInfoToFltResp(fctx.originalResponse, ri)
		defer mw.putFltResp(fltResp)

		respRes, err := f.FilterResponse(ctx, fltResp)
		if err != nil {
			errcoll.Collect(ctx, mw.errColl, mw.logger, "filtering response", err)
		}

		fctx.responseResult = respRes
	}

	fctx.elapsed += time.Since(start)
}

// reqInfoToFltResp converts data from a DNS response and request info into a
// *filter.Response.  The returned response data should be put back into
// the pool by using [Middleware.putFltResp].
func (mw *Middleware) reqInfoToFltResp(
	resp *dns.Msg,
	ri *agd.RequestInfo,
) (fltResp *filter.Response) {
	fltResp = mw.fltRespPool.Get()

	// NOTE:  Fill all fields of fltResp since it is reused from the pool.
	fltResp.DNS = resp
	fltResp.RemoteIP = ri.RemoteIP

	if _, d := ri.DeviceData(); d != nil {
		fltResp.ClientName = string(d.Name)
	} else {
		fltResp.ClientName = ""
	}

	return fltResp
}

// putFltResp sets resp.DNS to nil, to prevent the message being contained in
// the pool, which can lead to conflicts with the cloner of the middleware, and
// puts resp back into the pool.
func (mw *Middleware) putFltResp(resp *filter.Response) {
	resp.DNS = nil
	mw.fltRespPool.Put(resp)
}

// filteringData returns the data necessary for request information recording
// from the filtering context.
func filteringData(
	fctx *filteringContext,
) (id filter.ID, text filter.RuleText, blocked bool) {
	if fctx.requestResult != nil {
		return resultData(fctx.requestResult, "reqRes")
	}

	return resultData(fctx.responseResult, "respRes")
}

// resultData returns the data necessary for request information recording from
// one filtering result.  argName is used to provide better error handling.
func resultData(
	res filter.Result,
	argName string,
) (id filter.ID, text filter.RuleText, blocked bool) {
	if res == nil {
		return filter.IDNone, "", false
	}

	id, text = res.MatchedRule()
	switch res := res.(type) {
	case *filter.ResultAllowed:
		blocked = false
	case
		*filter.ResultBlocked,
		*filter.ResultModifiedResponse,
		*filter.ResultModifiedRequest:
		blocked = true
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(&agd.ArgumentError{
			Name:    argName,
			Message: fmt.Sprintf("unexpected type %T", res),
		})
	}

	return id, text, blocked
}

// setFilteredResponse sets the response in fctx if the filtering results
// require that.  After calling setFilteredResponse, fctx.filteredResponse will
// not be nil.  All errors are reported using [Middleware.reportf].  fctx and ri
// must not be nil.
func (mw *Middleware) setFilteredResponse(
	ctx context.Context,
	fctx *filteringContext,
	ri *agd.RequestInfo,
) {
	switch reqRes := fctx.requestResult.(type) {
	case nil:
		mw.setFilteredResponseNoReq(ctx, fctx, ri)
	case *filter.ResultBlocked:
		blockingMode := resultBlockingMode(ri, reqRes)

		mw.setFilteredResponseFromBlockingMode(ctx, fctx, ri, blockingMode)
	case *filter.ResultAllowed:
		fctx.filteredResponse = fctx.originalResponse
	case *filter.ResultModifiedRequest:
		blockingMode := filterBlockingMode(ri, reqRes)
		if blockingMode != nil {
			mw.setFilteredResponseFromBlockingMode(ctx, fctx, ri, blockingMode)

			return
		}

		fctx.filteredResponse = fctx.originalResponse
	case *filter.ResultModifiedResponse:
		blockingMode := filterBlockingMode(ri, reqRes)
		if blockingMode != nil {
			mw.setFilteredResponseFromBlockingMode(ctx, fctx, ri, blockingMode)

			return
		}

		// Only use the request filtering result in case it's already a
		// response.  Otherwise, it's a CNAME rewrite result, which isn't
		// filtered after resolving.
		fctx.filteredResponse = reqRes.Msg
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(&agd.ArgumentError{
			Name:    "reqRes",
			Message: fmt.Sprintf("unexpected type %T", reqRes),
		})
	}
}

// setFilteredResponseFromBlockingMode sets the response in fctx if for the
// given blocking mode.  After calling, fctx.filteredResponse will not be nil.
// All errors are reported using [Middleware.reportf].  fctx and ri must not be
// nil.
func (mw *Middleware) setFilteredResponseFromBlockingMode(
	ctx context.Context,
	fctx *filteringContext,
	ri *agd.RequestInfo,
	blockingMode dnsmsg.BlockingMode,
) {
	var err error
	fctx.filteredResponse, err = ri.Messages.NewBlockedResp(fctx.originalRequest, blockingMode)
	if err != nil {
		errcoll.Collect(ctx, mw.errColl, mw.logger, "creating blocked resp for filtered req", err)

		fctx.filteredResponse = fctx.originalResponse
	}
}

// setFilteredResponseNoReq sets the response in fctx if the response filtering
// results require that.  After calling setFilteredResponseNoReq,
// fctx.filteredResponse will not be nil.  All errors are reported using
// [Middleware.reportf].  Note that rewrite results are not applied to
// responses.
func (mw *Middleware) setFilteredResponseNoReq(
	ctx context.Context,
	fctx *filteringContext,
	ri *agd.RequestInfo,
) {
	switch respRes := fctx.responseResult.(type) {
	case nil, *filter.ResultAllowed:
		fctx.filteredResponse = fctx.originalResponse
	case *filter.ResultBlocked:
		blockingMode := resultBlockingMode(ri, respRes)

		var err error
		fctx.filteredResponse, err = ri.Messages.NewBlockedResp(fctx.originalRequest, blockingMode)
		if err != nil {
			errcoll.Collect(
				ctx,
				mw.errColl,
				mw.logger,
				"creating blocked resp for filtered resp",
				err,
			)
			fctx.filteredResponse = fctx.originalResponse
		}
	default:
		// Consider [*filter.ResultModifiedResponse] and
		// [*filter.ResultModifiedRequest] as unrecoverable programmer errors
		// because rewrites are not applied to responses.  And unhandled sum
		// type members as well.
		panic(&agd.ArgumentError{
			Name:    "respRes",
			Message: fmt.Sprintf("unexpected type %T", respRes),
		})
	}
}

// resultBlockingMode returns the blocking mode for the given filtering result,
// returns profile's blocking mode if the result is not related to adult
// blocking or safe browsing filters.  ri must not be nil.
//
// TODO(a.garipov):  Remove this temp solution by improving blocking mode API.
func resultBlockingMode(ri *agd.RequestInfo, res filter.Result) (m dnsmsg.BlockingMode) {
	profile, _ := ri.DeviceData()
	if profile == nil {
		return nil
	}

	fltID, _ := res.MatchedRule()
	switch fltID {
	case filter.IDAdultBlocking:
		return cmp.Or(profile.AdultBlockingMode, profile.BlockingMode)
	case filter.IDSafeBrowsing:
		return cmp.Or(profile.SafeBrowsingBlockingMode, profile.BlockingMode)
	}

	return profile.BlockingMode
}

// filterBlockingMode returns the blocking mode for the given filtering result,
// returns nil if the result is not related to adult blocking or safe browsing
// filters.  ri must not be nil.
//
// TODO(a.garipov):  Remove this temp solution by improving blocking mode API.
func filterBlockingMode(ri *agd.RequestInfo, res filter.Result) (m dnsmsg.BlockingMode) {
	profile, _ := ri.DeviceData()
	if profile == nil {
		return nil
	}

	fltID, _ := res.MatchedRule()
	switch fltID {
	case filter.IDAdultBlocking:
		return profile.AdultBlockingMode
	case filter.IDSafeBrowsing:
		return profile.SafeBrowsingBlockingMode
	}

	return nil
}
