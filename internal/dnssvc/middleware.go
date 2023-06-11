package dnssvc

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// Middlewares

// Main DNS Service Middleware

// Wrap implements the dnsserver.Middleware interface for *Service.
func (svc *Service) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
	return &svcHandler{
		svc:  svc,
		next: h,
	}
}

// svcHandler implements the [dnsserver.Handler] interface and will be used
// as a [dnsserver.Handler] that the Service middleware returns from the Wrap
// function call.
type svcHandler struct {
	svc  *Service
	next dnsserver.Handler
}

// type check
var _ dnsserver.Handler = (*svcHandler)(nil)

// ServeDNS implements the [dnsserver.Handler] interface for *svcHandler.
func (mh *svcHandler) ServeDNS(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
) (err error) {
	isDebug := req.Question[0].Qclass == dns.ClassCHAOS
	if isDebug {
		req.Question[0].Qclass = dns.ClassINET
	}

	reqID, _ := agd.RequestIDFromContext(ctx)
	raddr := rw.RemoteAddr()
	optlog.Debug2("processing request %q from %s", reqID, raddr)
	defer optlog.Debug2("finished processing request %q from %s", reqID, raddr)

	reqInfo := agd.MustRequestInfoFromContext(ctx)
	flt := mh.svc.fltStrg.FilterFromContext(ctx, reqInfo)

	modReq, reqRes, elapsedReq := mh.svc.filterRequest(ctx, req, flt, reqInfo)

	nwrw := makeNonWriter(rw)
	if modReq != nil {
		// Modified request is set only if the request was modified by a CNAME
		// rewrite rule, so resolve the request as if it was for the rewritten
		// name.

		// Clone the request informaton and replace the host name with the
		// rewritten one, since the request information from current context
		// must only be accessed for reading, see [agd.RequestInfo].  Shallow
		// copy is enough, because we only change the [agd.RequestInfo.Host]
		// field, which is a string.
		modReqInfo := &agd.RequestInfo{}
		*modReqInfo = *reqInfo
		modReqInfo.Host = strings.ToLower(strings.TrimSuffix(modReq.Question[0].Name, "."))

		modReqCtx := agd.ContextWithRequestInfo(ctx, modReqInfo)

		optlog.Debug2(
			"dnssvc: request for %q rewritten to %q by CNAME rewrite rule",
			reqInfo.Host,
			modReqInfo.Host,
		)

		err = mh.next.ServeDNS(modReqCtx, nwrw, modReq)
	} else {
		err = mh.next.ServeDNS(ctx, nwrw, req)
	}
	if err != nil {
		return err
	}

	origResp := nwrw.Msg()
	respRes, elapsedResp := mh.svc.filterResponse(ctx, req, origResp, flt, reqInfo, modReq)

	mh.svc.reportMetrics(reqInfo, reqRes, respRes, elapsedReq+elapsedResp)

	if isDebug {
		return mh.svc.writeDebugResponse(ctx, rw, req, origResp, reqRes, respRes)
	}

	resp, err := writeFilteredResp(ctx, reqInfo, rw, req, origResp, reqRes, respRes)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	mh.svc.recordQueryInfo(ctx, req, resp, origResp, reqInfo, reqRes, respRes)

	return nil
}

// makeNonWriter makes rw a *dnsserver.NonWriterResponseWriter unless it already
// is one, in which case it just returns it.
func makeNonWriter(rw dnsserver.ResponseWriter) (nwrw *dnsserver.NonWriterResponseWriter) {
	nwrw, ok := rw.(*dnsserver.NonWriterResponseWriter)
	if ok {
		return nwrw
	}

	return dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
}

// rewrittenRequest returns a request from res in case it's a CNAME rewrite, and
// returns nil otherwise.  Note that the returned message is always a request
// since any other rewrite rule type turns into response.
func rewrittenRequest(res filter.Result) (req *dns.Msg) {
	if res, ok := res.(*filter.ResultModified); ok && !res.Msg.Response {
		return res.Msg
	}

	return nil
}

// filterRequest applies f to req and returns the result of filtering.  If the
// result is the CNAME rewrite, it also returns the modified request to resolve.
// It also returns the time elapsed on filtering.
func (svc *Service) filterRequest(
	ctx context.Context,
	req *dns.Msg,
	f filter.Interface,
	ri *agd.RequestInfo,
) (modReq *dns.Msg, reqRes filter.Result, elapsed time.Duration) {
	start := time.Now()
	reqRes, err := f.FilterRequest(ctx, req, ri)
	if err != nil {
		svc.reportf(ctx, "filtering request: %w", err)
	}

	// Consider this operation related to filtering and account the elapsed
	// time.
	modReq = rewrittenRequest(reqRes)

	return modReq, reqRes, time.Since(start)
}

// filterResponse applies f to resp and returns the result of filtering.  If
// origReq has a different question name than resp, the request assumed being
// CNAME-rewritten and no filtering performed on resp, the CNAME is prepended to
// resp answer section instead.  It also returns the time elapsed on filtering.
func (svc *Service) filterResponse(
	ctx context.Context,
	req *dns.Msg,
	resp *dns.Msg,
	f filter.Interface,
	ri *agd.RequestInfo,
	modReq *dns.Msg,
) (respRes filter.Result, elapsed time.Duration) {
	start := time.Now()

	if modReq != nil {
		// Return the request name to its original state, since it was
		// previously rewritten by CNAME rewrite rule.
		resp.Question[0] = req.Question[0]

		// Prepend the CNAME answer to the response and don't filter it.
		var rr dns.RR = ri.Messages.NewAnswerCNAME(req, modReq.Question[0].Name)
		resp.Answer = slices.Insert(resp.Answer, 0, rr)

		// Also consider this operation related to filtering and account the
		// elapsed time.
		return nil, time.Since(start)
	}

	respRes, err := f.FilterResponse(ctx, resp, ri)
	if err != nil {
		svc.reportf(ctx, "filtering response: %w", err)
	}

	return respRes, time.Since(start)
}

// reportMetrics extracts filtering metrics data from the context and reports it
// to Prometheus.
func (svc *Service) reportMetrics(
	ri *agd.RequestInfo,
	reqRes filter.Result,
	respRes filter.Result,
	elapsedFiltering time.Duration,
) {
	var ctry, cont string
	asn := "0"
	if l := ri.Location; l != nil {
		ctry, cont = string(l.Country), string(l.Continent)
		asn = strconv.FormatUint(uint64(l.ASN), 10)
	}

	// Here and below stick to using WithLabelValues instead of With in order
	// to avoid extra allocations on prometheus.Labels.

	metrics.DNSSvcRequestByCountryTotal.WithLabelValues(cont, ctry).Inc()
	metrics.DNSSvcRequestByASNTotal.WithLabelValues(ctry, asn).Inc()

	id, _, isBlocked := filteringData(reqRes, respRes)
	metrics.DNSSvcRequestByFilterTotal.WithLabelValues(
		string(id),
		metrics.BoolString(ri.Profile == nil),
	).Inc()

	metrics.DNSSvcFilteringDuration.Observe(elapsedFiltering.Seconds())
	metrics.DNSSvcUsersCountUpdate(ri.RemoteIP)

	if svc.researchMetrics {
		metrics.ReportResearchMetrics(ri, id, isBlocked)
	}
}

// reportf is a helper method for reporting non-critical errors.
func (svc *Service) reportf(ctx context.Context, format string, args ...any) {
	agd.Collectf(ctx, svc.errColl, "dnssvc: "+format, args...)
}
