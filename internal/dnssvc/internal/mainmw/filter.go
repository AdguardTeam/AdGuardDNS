package mainmw

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
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

	reqRes, err := f.FilterRequest(ctx, fctx.originalRequest, ri)
	if err != nil {
		mw.reportf(ctx, "filtering request: %w", err)
	}

	if mod, ok := reqRes.(*filter.ResultModifiedRequest); ok {
		fctx.modifiedRequest = mod.Msg
	}

	fctx.requestResult = reqRes
	fctx.elapsed += time.Since(start)
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
		respRes, err := f.FilterResponse(ctx, fctx.originalResponse, ri)
		if err != nil {
			mw.reportf(ctx, "filtering response: %w", err)
		}

		fctx.responseResult = respRes
	}

	fctx.elapsed += time.Since(start)
}

// filteringData returns the data necessary for request information recording
// from the filtering context.
func filteringData(
	fctx *filteringContext,
) (id agd.FilterListID, text agd.FilterRuleText, blocked bool) {
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
) (id agd.FilterListID, text agd.FilterRuleText, blocked bool) {
	if res == nil {
		return agd.FilterListIDNone, "", false
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
// not be nil.  All errors are reported using [Middleware.reportf].
func (mw *Middleware) setFilteredResponse(
	ctx context.Context,
	fctx *filteringContext,
	ri *agd.RequestInfo,
) {
	switch reqRes := fctx.requestResult.(type) {
	case nil:
		mw.setFilteredResponseNoReq(ctx, fctx, ri)
	case *filter.ResultBlocked:
		var err error
		fctx.filteredResponse, err = ri.Messages.NewBlockedResp(fctx.originalRequest)
		if err != nil {
			mw.reportf(ctx, "creating blocked resp for filtered req: %w", err)
			fctx.filteredResponse = fctx.originalResponse
		}
	case *filter.ResultAllowed, *filter.ResultModifiedRequest:
		fctx.filteredResponse = fctx.originalResponse
	case *filter.ResultModifiedResponse:
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
		var err error
		fctx.filteredResponse, err = ri.Messages.NewBlockedResp(fctx.originalRequest)
		if err != nil {
			mw.reportf(ctx, "creating blocked resp for filtered resp: %w", err)
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
